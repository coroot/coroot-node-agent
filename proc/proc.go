package proc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/cgroup"
)

var (
	root           = "/proc"
	bootTimeLock   sync.Mutex
	cachedBootTime int64
)

func Path(pid uint32, subpath ...string) string {
	return path.Join(append([]string{root, strconv.Itoa(int(pid))}, subpath...)...)
}

func HostPath(p string) string {
	return Path(1, "root", p)
}

func GetCmdline(pid uint32) []byte {
	cmdline, err := os.ReadFile(Path(pid, "cmdline"))
	if err != nil {
		return nil
	}
	return bytes.TrimSuffix(cmdline, []byte{0})
}

func GetNsPid(pid uint32) (uint32, error) {
	data, err := os.ReadFile(Path(pid, "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "NSpid:" {
			var f string
			switch len(fields) {
			case 2:
				f = fields[1]
			case 3:
				f = fields[2]
			default:
				return 0, errors.New("invalid NSpid value")
			}
			nsPid, err := strconv.ParseUint(f, 10, 32)
			if err != nil {
				return 0, fmt.Errorf("invalid NSpid value: %w", err)
			}
			return uint32(nsPid), nil
		}
	}
	return 0, errors.New("NSpid not found")
}

func ReadCgroup(pid uint32) (*cgroup.Cgroup, error) {
	return cgroup.NewFromProcessCgroupFile(Path(pid, "cgroup"))
}

// GetStartTime returns the process start time derived from /proc/<pid>/stat
func GetStartTime(pid uint32) time.Time {
	data, err := os.ReadFile(Path(pid, "stat"))
	if err != nil {
		return time.Time{}
	}
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 {
		return time.Time{}
	}
	fields := strings.Fields(s[idx+1:])
	if len(fields) < 20 {
		return time.Time{}
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}
	}
	btime, err := bootTime()
	if err != nil {
		return time.Time{}
	}
	return time.Unix(btime+int64(float64(startTicks)/100), 0)
}

func bootTime() (int64, error) {
	bootTimeLock.Lock()
	defer bootTimeLock.Unlock()
	if cachedBootTime != 0 {
		return cachedBootTime, nil
	}
	data, err := os.ReadFile(root + "/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0, fmt.Errorf("invalid btime line in /proc/stat: %q", line)
		}
		btime, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		cachedBootTime = btime
		return btime, nil
	}
	return 0, fmt.Errorf("btime not found in /proc/stat")
}

func ListPids() ([]uint32, error) {
	root, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dirs, err := root.Readdirnames(0)
	if err != nil {
		return nil, err
	}
	res := make([]uint32, 0, len(dirs))
	for _, dir := range dirs {
		pid64, err := strconv.ParseUint(dir, 10, 32)
		if err != nil {
			continue
		}
		res = append(res, uint32(pid64))
	}
	return res, nil
}
