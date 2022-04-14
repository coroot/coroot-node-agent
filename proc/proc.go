package proc

import (
	"github.com/coroot/coroot-node-agent/cgroup"
	"os"
	"path"
	"strconv"
)

var root = "/proc"

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
	return cmdline
}

func ReadCgroup(pid uint32) (*cgroup.Cgroup, error) {
	return cgroup.NewFromProcessCgroupFile(Path(pid, "cgroup"))
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
