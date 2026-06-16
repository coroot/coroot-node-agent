//go:build windows

package proc

import (
	"errors"
	"path/filepath"
	"strconv"

	"github.com/coroot/coroot-node-agent/cgroup"
)

var root = "/proc"

type Flags struct {
	EbpfProfilingDisabled bool
	EbpfTracesDisabled    bool
	LogMonitoringDisabled bool
}

type MountInfo struct {
	MountID        string
	ParentID       string
	MajorMinor     string
	Root           string
	MountPoint     string
	Options        []string
	OptionalFields []string
	Filesystem     string
	MountSource    string
	SuperOptions   []string
}

type FSStat struct {
	UsagePercent float64
	UsageBytes   float64
	Capacity     float64
}

type Fd struct {
	Pid      uint32
	FD       uint64
	Dest     string
	RealPath string
}

type FdInfo struct {
	Flags uint32
}

type Sock struct {
	Inode string
}

func Path(pid uint32, subpath ...string) string {
	parts := []string{root, strconv.Itoa(int(pid))}
	parts = append(parts, subpath...)
	return filepath.Join(parts...)
}

func HostPath(p string) string {
	return p
}

func GetCmdline(pid uint32) []byte {
	return nil
}

func GetNsPid(pid uint32) (uint32, error) {
	return pid, nil
}

func GetFlags(pid uint32) (Flags, error) {
	return Flags{}, nil
}

func ListPids() ([]uint32, error) {
	return nil, errors.ErrUnsupported
}

func ReadCgroup(pid uint32) (*cgroup.Cgroup, error) {
	return nil, errors.ErrUnsupported
}
