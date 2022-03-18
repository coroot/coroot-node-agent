package cgroup

import (
	"fmt"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"io/ioutil"
	"k8s.io/klog/v2"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

var (
	cgRoot = *flags.CgroupRoot

	dockerIdRegexp      = regexp.MustCompile(`([a-z0-9]{64})`)
	crioIdRegexp        = regexp.MustCompile(`crio-([a-z0-9]{64})`)
	containerdIdRegexp  = regexp.MustCompile(`cri-containerd-([a-z0-9]{64})`)
	lxcIdRegexp         = regexp.MustCompile(`/lxc/([^/]+)`)
	systemSliceIdRegexp = regexp.MustCompile(`(/system\.slice/([^/]+))`)
)

type Version uint8

const (
	V1 Version = iota
	V2
)

type ContainerType uint8

const (
	ContainerTypeUnknown ContainerType = iota
	ContainerTypeStandaloneProcess
	ContainerTypeDocker
	ContainerTypeCrio
	ContainerTypeContainerd
	ContainerTypeLxc
	ContainerTypeSystemdService
)

func (t ContainerType) String() string {
	switch t {
	case ContainerTypeStandaloneProcess:
		return "standalone"
	case ContainerTypeDocker:
		return "docker"
	case ContainerTypeCrio:
		return "crio"
	case ContainerTypeContainerd:
		return "cri-containerd"
	case ContainerTypeLxc:
		return "lxc"
	case ContainerTypeSystemdService:
		return "systemd"
	default:
		return "unknown"
	}
}

type Stats struct {
	CpuUsageSeconds      float64
	ThrottledTimeSeconds float64
	CpuQuotaCores        float64

	MemoryRssBytes   float64
	MemoryCacheBytes float64
	MemoryLimitBytes float64

	Blkio map[string]BlkioStat
}

type Cgroup struct {
	Id            string
	Version       Version
	ContainerType ContainerType
	ContainerId   string

	prevStats *Stats

	subsystems map[string]string
}

func (cg *Cgroup) GetStats() *Stats {
	cur, err := cg.getCurrentStats()
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningf("failed to get cgroup stats: %s", err)
		}
		return nil
	}
	var res *Stats
	if cg.prevStats != nil {
		res = &Stats{
			CpuUsageSeconds:      cur.CpuUsageSeconds - cg.prevStats.CpuUsageSeconds,
			ThrottledTimeSeconds: cur.ThrottledTimeSeconds - cg.prevStats.ThrottledTimeSeconds,
			CpuQuotaCores:        cur.CpuQuotaCores,
			MemoryRssBytes:       cur.MemoryRssBytes,
			MemoryCacheBytes:     cur.MemoryCacheBytes,
			MemoryLimitBytes:     cur.MemoryLimitBytes,
			Blkio:                map[string]BlkioStat{},
		}
		for majorMinor, stat := range cur.Blkio {
			prev, ok := cg.prevStats.Blkio[majorMinor]
			if !ok {
				continue
			}
			res.Blkio[majorMinor] = BlkioStat{
				ReadOps:      stat.ReadOps - prev.ReadOps,
				WriteOps:     stat.WriteOps - prev.WriteOps,
				ReadBytes:    stat.ReadBytes - prev.ReadBytes,
				WrittenBytes: stat.WrittenBytes - prev.WrittenBytes,
			}
		}
	}
	cg.prevStats = cur
	return res
}

func (cg *Cgroup) getCurrentStats() (*Stats, error) {
	stats := &Stats{}
	var err error
	if stats.CpuUsageSeconds, err = cg.CpuUsageSeconds(); err != nil {
		return nil, err
	}
	if stats.ThrottledTimeSeconds, err = cg.ThrottledTimeSeconds(); err != nil {
		return nil, err
	}
	if stats.CpuQuotaCores, err = cg.CpuQuotaCores(); err != nil {
		return nil, err
	}
	m, err := cg.MemoryStat()
	if err != nil {
		return nil, err
	}
	stats.MemoryRssBytes = float64(m.RSS)
	stats.MemoryCacheBytes = float64(m.Cache)
	l, err := cg.MemoryLimitBytes()
	if err != nil {
		return nil, err
	}
	stats.MemoryLimitBytes = float64(l)
	stats.Blkio, err = cg.BlkioStat()
	if err != nil {
		return nil, err
	}
	return stats, nil
}

func (cg *Cgroup) CreatedAt() time.Time {
	fi, err := os.Stat(path.Join(cgRoot, "cpu", cg.subsystems["cpu"]))
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Errorln(err)
		}
		return time.Time{}
	}
	return fi.ModTime()
}

func NewFromProcessCgroupFile(filePath string) (*Cgroup, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	cg := &Cgroup{
		subsystems: map[string]string{},
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		for _, cgType := range strings.Split(parts[1], ",") {
			cg.subsystems[cgType] = parts[2]
		}
	}
	if cg.Id = cg.subsystems["cpu"]; cg.Id != "" {
		cg.Version = V1
	} else {
		cg.Id = cg.subsystems[""]
		cg.Version = V2
	}
	if cg.ContainerType, cg.ContainerId, err = containerByCgroup(cg.Id); err != nil {
		return nil, err
	}
	return cg, nil
}

func containerByCgroup(path string) (ContainerType, string, error) {
	parts := strings.Split(strings.TrimLeft(path, "/"), "/")
	if len(parts) < 2 {
		return ContainerTypeStandaloneProcess, "", nil
	}
	prefix := parts[0]
	if prefix == "user.slice" || prefix == "init.scope" {
		return ContainerTypeStandaloneProcess, "", nil
	}
	if prefix == "docker" || (prefix == "system.slice" && strings.HasPrefix(parts[1], "docker")) {
		matches := dockerIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid docker cgroup %s", path)
		}
		return ContainerTypeDocker, matches[1], nil
	}
	if prefix == "kubepods" || prefix == "kubepods.slice" {
		crioMatches := crioIdRegexp.FindStringSubmatch(path)
		if crioMatches != nil {
			return ContainerTypeCrio, crioMatches[1], nil
		}
		containerdMatches := containerdIdRegexp.FindStringSubmatch(path)
		if containerdMatches != nil {
			return ContainerTypeContainerd, containerdMatches[1], nil
		}
		matches := dockerIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid docker cgroup %s", path)
		}
		return ContainerTypeDocker, matches[1], nil
	}
	if prefix == "lxc" {
		matches := lxcIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid lxc cgroup %s", path)
		}
		return ContainerTypeLxc, matches[1], nil
	}
	if prefix == "system.slice" {
		matches := systemSliceIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid systemd cgroup %s", path)
		}
		return ContainerTypeSystemdService, matches[1], nil
	}
	return ContainerTypeUnknown, "", fmt.Errorf("unknown container: %s", path)
}
