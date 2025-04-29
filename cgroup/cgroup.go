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
	cgRoot  = *flags.CgroupRoot
	cg2Root = *flags.CgroupRoot

	baseCgroupPath = ""

	dockerIdRegexp      = regexp.MustCompile(`([a-z0-9]{64})`)
	crioIdRegexp        = regexp.MustCompile(`crio-([a-z0-9]{64})`)
	containerdIdRegexp  = regexp.MustCompile(`cri-containerd[-:]([a-z0-9]{64})`)
	lxcIdRegexp         = regexp.MustCompile(`/lxc/([^/]+)`)
	systemSliceIdRegexp = regexp.MustCompile(`(/(system|runtime|reserved)\.slice/([^/]+))`)
	talosIdRegexp       = regexp.MustCompile(`/(system|podruntime)/([^/]+)`)
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
	ContainerTypeTalosRuntime
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
	ContainerType ContainerType
	ContainerId   string

	subsystems map[string]string
}

func (cg *Cgroup) getId() string {
	v2 := cg.subsystems[""]
	cpu := cg.subsystems["cpu"]
	mem := cg.subsystems["memory"]
	name := cg.subsystems["name=systemd"]

	id := v2
	if strings.HasPrefix(cpu, "/kubepods") {
		return cpu
	}
	if strings.HasPrefix(mem, "/kubepods") {
		return mem
	}
	if id == "" {
		id = cpu
	}
	if id == "" {
		id = mem
	}
	if id == "" {
		return name
	}
	return id
}

func (cg *Cgroup) CreatedAt() time.Time {
	var p string
	if sp := cg.subsystems[""]; sp != "" { //v2
		p = path.Join(cg2Root, sp)
	} else if sp = cg.subsystems["cpu"]; sp != "" {
		p = path.Join(cgRoot, "cpu", sp)
	} else if sp = cg.subsystems["memory"]; sp != "" {
		p = path.Join(cgRoot, "memory", sp)
	}
	if p == "" {
		return time.Time{}
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
			p := path.Join(baseCgroupPath, parts[2])
			switch p {
			case "/", "/init.scope":
				continue
			}
			cg.subsystems[cgType] = p
		}
	}

	cg.Id = cg.getId()
	if cg.ContainerType, cg.ContainerId, err = containerByCgroup(cg.Id); err != nil {
		return nil, err
	}
	return cg, nil
}

func containerByCgroup(cgroupPath string) (ContainerType, string, error) {
	parts := strings.Split(strings.TrimLeft(cgroupPath, "/"), "/")
	if cgroupPath == "/init" {
		return ContainerTypeTalosRuntime, "/talos/init", nil
	}
	if len(parts) < 2 {
		return ContainerTypeStandaloneProcess, "", nil
	}
	prefix := parts[0]
	if prefix == "user.slice" || prefix == "init.scope" {
		return ContainerTypeStandaloneProcess, "", nil
	}
	if prefix == "docker" || (prefix == "system.slice" && strings.HasPrefix(parts[1], "docker-")) {
		matches := dockerIdRegexp.FindStringSubmatch(cgroupPath)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid docker cgroup %s", cgroupPath)
		}
		return ContainerTypeDocker, matches[1], nil
	}
	if strings.Contains(cgroupPath, "kubepods") {
		crioMatches := crioIdRegexp.FindStringSubmatch(cgroupPath)
		if crioMatches != nil {
			return ContainerTypeCrio, crioMatches[1], nil
		}
		if strings.Contains(cgroupPath, "crio-conmon-") {
			return ContainerTypeUnknown, "", nil
		}
		containerdMatches := containerdIdRegexp.FindStringSubmatch(cgroupPath)
		if containerdMatches != nil {
			return ContainerTypeContainerd, containerdMatches[1], nil
		}
		matches := dockerIdRegexp.FindStringSubmatch(cgroupPath)
		if matches == nil {
			return ContainerTypeSandbox, "", nil
		}
		return ContainerTypeDocker, matches[1], nil
	}
	if prefix == "lxc" {
		matches := lxcIdRegexp.FindStringSubmatch(cgroupPath)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid lxc cgroup %s", cgroupPath)
		}
		return ContainerTypeLxc, matches[1], nil
	}
	if prefix == "system" || prefix == "podruntime" {
		matches := talosIdRegexp.FindStringSubmatch(cgroupPath)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid talos runtime cgroup %s", cgroupPath)
		}
		return ContainerTypeTalosRuntime, path.Join("/talos/", matches[2]), nil
	}
	if prefix == "system.slice" || prefix == "runtime.slice" || prefix == "reserved.slice" {
		matches := systemSliceIdRegexp.FindStringSubmatch(cgroupPath)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid systemd cgroup %s", cgroupPath)
		}
		return ContainerTypeSystemdService, strings.Replace(matches[1], "\\x2d", "-", -1), nil
	}
	return ContainerTypeUnknown, "", fmt.Errorf("unknown container: %s", cgroupPath)
}
