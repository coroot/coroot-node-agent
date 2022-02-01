package proc

import (
	"os"
	"strconv"
	"strings"
)

type FdInfo struct {
	MntId string
	Flags int
	Dest  string
}

func GetFdInfo(pid uint32, fd uint32) *FdInfo {
	fds := strconv.Itoa(int(fd))
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
