package proc

import (
	"os"
	"path"
	"strconv"
	"strings"
)

type Fd struct {
	Fd   uint64
	Dest string

	SocketInode string
}

func ReadFds(pid uint32) ([]Fd, error) {
	fdDir := Path(pid, "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	res := make([]Fd, 0, len(entries))
	for _, entry := range entries {
		fd, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil {
			continue
		}
		dest, err := os.Readlink(path.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		var socketInode string
		if strings.HasPrefix(dest, "socket:[") && strings.HasSuffix(dest, "]") {
			socketInode = dest[len("socket:[") : len(dest)-1]
		}
		res = append(res, Fd{Fd: fd, Dest: dest, SocketInode: socketInode})
	}
	return res, nil
}

type FdInfo struct {
	MntId string
	Flags int
	Dest  string
}

func GetFdInfo(pid uint32, fd uint64) *FdInfo {
	fds := strconv.FormatUint(fd, 10)
	data, err := os.ReadFile(Path(pid, "fdinfo", fds))
	if err != nil {
		return nil
	}
	dest, err := os.Readlink(Path(pid, "fd", fds))
	if err != nil {
		return nil
	}
	res := FdInfo{Dest: dest}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "mnt_id:") {
			res.MntId = strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:"))
			continue
		}
		if strings.HasPrefix(line, "flags:") {
			flags, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "flags:")), 8, 32)
			res.Flags = int(flags)
			continue
		}
	}
	return &res
}
