//go:build windows

package proc

import (
	"errors"
	"path/filepath"
	"strconv"
	"unsafe"

	"github.com/coroot/coroot-node-agent/cgroup"
	"golang.org/x/sys/windows"
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
	image, err := processImagePath(pid)
	if err != nil || image == "" {
		return nil
	}
	return []byte(image)
}

func GetNsPid(pid uint32) (uint32, error) {
	return pid, nil
}

func GetFlags(pid uint32) (Flags, error) {
	return Flags{}, nil
}

func ListPids() ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ProcessEntry32{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}
	var pids []uint32
	for {
		if entry.ProcessID != 0 {
			pids = append(pids, entry.ProcessID)
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return pids, err
		}
	}
	return pids, nil
}

func ReadCgroup(pid uint32) (*cgroup.Cgroup, error) {
	return nil, errors.ErrUnsupported
}

func processImagePath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}
