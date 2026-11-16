package proc

import (
	"bytes"
	"os"
	"path"
	"strconv"
	"strings"
)

// Status holds the fields of /proc/<pid>/status that describe the address space, memory and scheduling of a process.
type Status struct {
	VmSizeBytes          float64
	VmDataBytes          float64
	VmSwapBytes          float64
	RssBytes             float64
	RssAnonBytes         float64
	RssFileBytes         float64
	RssShmemBytes        float64
	Threads              float64
	VoluntaryCtxSwitches float64
	InvoluntaryCtxSwitch float64
}

var statusKb = map[string]func(*Status, float64){
	"VmSize":   func(s *Status, v float64) { s.VmSizeBytes = v },
	"VmData":   func(s *Status, v float64) { s.VmDataBytes = v },
	"VmSwap":   func(s *Status, v float64) { s.VmSwapBytes = v },
	"VmRSS":    func(s *Status, v float64) { s.RssBytes = v },
	"RssAnon":  func(s *Status, v float64) { s.RssAnonBytes = v },
	"RssFile":  func(s *Status, v float64) { s.RssFileBytes = v },
	"RssShmem": func(s *Status, v float64) { s.RssShmemBytes = v },
}

func ReadStatus(pid uint32) (*Status, error) {
	data, err := os.ReadFile(Path(pid, "status"))
	if err != nil {
		return nil, err
	}
	return parseStatus(data), nil
}

func parseStatus(data []byte) *Status {
	s := &Status{}
	for _, line := range strings.Split(string(data), "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key, val := line[:i], strings.Fields(line[i+1:])
		if len(val) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(val[0], 64)
		if err != nil {
			continue
		}
		switch key {
		case "Threads":
			s.Threads = v
		case "voluntary_ctxt_switches":
			s.VoluntaryCtxSwitches = v
		case "nonvoluntary_ctxt_switches":
			s.InvoluntaryCtxSwitch = v
		default:
			if set, ok := statusKb[key]; ok {
				set(s, v*1024)
			}
		}
	}
	return s
}

// ReadFaults returns the minor and major page faults of a process from /proc/<pid>/stat.
func ReadFaults(pid uint32) (minor, major float64, err error) {
	data, err := os.ReadFile(Path(pid, "stat"))
	if err != nil {
		return 0, 0, err
	}
	minor, major = parseFaults(data)
	return minor, major, nil
}

func parseFaults(data []byte) (float64, float64) {
	// the command name is in parentheses and may contain spaces; fields start after the last ')'
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return 0, 0
	}
	f := strings.Fields(string(data[i+1:]))
	// after the command: state(0) ppid(1) pgrp(2) session(3) tty_nr(4) tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9)
	if len(f) < 10 {
		return 0, 0
	}
	minor, _ := strconv.ParseFloat(f[7], 64)
	major, _ := strconv.ParseFloat(f[9], 64)
	return minor, major
}

// FdStats counts the open file descriptors of a process by kind and reports the soft limit.
type FdStats struct {
	Total  float64
	Limit  float64
	ByKind map[string]float64
}

// ReadFdStats classifies the descriptors of a process. Processes with more than maxClassify descriptors are only counted.
func ReadFdStats(pid uint32, maxClassify int) (*FdStats, error) {
	fdDir := Path(pid, "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	res := &FdStats{Total: float64(len(entries)), ByKind: map[string]float64{}}
	res.Limit = readFdLimit(pid)
	if maxClassify > 0 && len(entries) > maxClassify {
		res.ByKind["unclassified"] = res.Total
		return res, nil
	}
	for _, e := range entries {
		dest, err := os.Readlink(path.Join(fdDir, e.Name()))
		if err != nil {
			res.Total--
			continue
		}
		res.ByKind[ClassifyFd(dest)]++
	}
	return res, nil
}

func readFdLimit(pid uint32) float64 {
	data, err := os.ReadFile(Path(pid, "limits"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Max open files") {
			f := strings.Fields(strings.TrimPrefix(line, "Max open files"))
			if len(f) > 0 {
				if f[0] == "unlimited" {
					return 0
				}
				v, _ := strconv.ParseFloat(f[0], 64)
				return v
			}
		}
	}
	return 0
}

// ClassifyFd maps the target of a /proc/<pid>/fd link to a small fixed set of kinds.
func ClassifyFd(dest string) string {
	switch {
	case strings.HasPrefix(dest, "socket:"):
		return "socket"
	case strings.HasPrefix(dest, "pipe:"):
		return "pipe"
	case strings.HasPrefix(dest, "anon_inode:"):
		name := strings.Trim(strings.TrimPrefix(dest, "anon_inode:"), "[]")
		switch name {
		case "eventfd", "eventpoll", "timerfd", "signalfd", "inotify":
			return strings.Replace(name, "eventpoll", "epoll", 1)
		}
		if strings.HasPrefix(name, "[infinibandevent") || strings.Contains(name, "infiniband") {
			return "ib_event"
		}
		return "anon_other"
	case strings.HasPrefix(dest, "/dev/infiniband/uverbs"):
		return "uverbs"
	case strings.HasPrefix(dest, "/dev/infiniband/rdma_cm"):
		return "rdma_cm"
	case strings.HasPrefix(dest, "/dev/nvidia"):
		return "nvidia"
	case strings.HasPrefix(dest, "/dev/shm/") || strings.HasPrefix(dest, "/memfd:"):
		return "shm"
	case strings.HasPrefix(dest, "/dev/"):
		return "device"
	case strings.HasPrefix(dest, "/"):
		return "file"
	}
	return "other"
}
