package proc

import (
	"os"
	"strings"
)

type MountInfo struct {
	MajorMinor string
	MountPoint string
}

func GetMountInfo(pid uint32) map[string]MountInfo {
	data, err := os.ReadFile(Path(pid, "mountinfo"))
	if err != nil {
		return nil
	}
	res := map[string]MountInfo{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if strings.HasPrefix(fields[2], "0:") {
			continue
		}
		res[fields[0]] = MountInfo{MajorMinor: fields[2], MountPoint: fields[4]}
	}
	return res
}
