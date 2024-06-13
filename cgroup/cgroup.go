package cgroup

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"k8s.io/klog/v2"
)

var (
	cgRoot = *flags.CgroupRoot

	baseCgroupPath = ""

	dockerIdRegexp      = regexp.MustCompile(`([a-z0-9]{64})`)
	crioIdRegexp        = regexp.MustCompile(`crio-([a-z0-9]{64})`)
	containerdIdRegexp  = regexp.MustCompile(`cri-containerd[-:]([a-z0-9]{64})`)
	lxcIdRegexp         = regexp.MustCompile(`/lxc/([^/]+)`)
	systemSliceIdRegexp = regexp.MustCompile(`(/(system|runtime)\.slice/([^/]+))`)
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
	ContainerTypeSandbox
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

type Cgroup struct {
	Id            string
	Version       Version
	ContainerType ContainerType
	ContainerId   string

	subsystems map[string]string
}

func (cg *Cgroup) CreatedAt() time.Time {
	p := path.Join(cgRoot, cg.subsystems[""]) //v2
	if cg.Version == V1 {
		p = path.Join(cgRoot, "cpu", cg.subsystems["cpu"])
	}
	fi, err := os.Stat(p)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Errorln(err)
		}
		return time.Time{}
	}
	return fi.ModTime()
}

func NewFromProcessCgroupFile(filePath string) (*Cgroup, error) {
	data, err := os.ReadFile(filePath)
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
			cg.subsystems[cgType] = path.Join(baseCgroupPath, parts[2])
		}
	}
	if p := cg.subsystems["name=systemd"]; p != "" {
		cg.Id = p
		cg.Version = V1
	} else if p = cg.subsystems["cpu"]; p != "" {
		cg.Id = p
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
	if prefix == "docker" || (prefix == "system.slice" && strings.HasPrefix(parts[1], "docker-")) {
		matches := dockerIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid docker cgroup %s", path)
		}
		return ContainerTypeDocker, matches[1], nil
	}
	if strings.Contains(path, "kubepods") {
		crioMatches := crioIdRegexp.FindStringSubmatch(path)
		if crioMatches != nil {
			return ContainerTypeCrio, crioMatches[1], nil
		}
		if strings.Contains(path, "crio-conmon-") {
			return ContainerTypeUnknown, "", nil
		}
		containerdMatches := containerdIdRegexp.FindStringSubmatch(path)
		if containerdMatches != nil {
			return ContainerTypeContainerd, containerdMatches[1], nil
		}
		matches := dockerIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeSandbox, "", nil
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
	if prefix == "system.slice" || prefix == "runtime.slice" {
		matches := systemSliceIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid systemd cgroup %s", path)
		}
		return ContainerTypeSystemdService, matches[1], nil
	}
	return ContainerTypeUnknown, "", fmt.Errorf("unknown container: %s", path)
}
