package proc

import (
	"os"
	"slices"
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
			switch getFsTypeFromMountInfo(fields) {
			case "zfs":
			default:
				continue
			}
		}
		res[fields[0]] = MountInfo{MajorMinor: fields[2], MountPoint: fields[4]}
	}
	return res
}

// https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html
func getFsTypeFromMountInfo(fields []string) string {
	if len(fields) < 7 {
		return ""
	}
	fields = fields[6:]
	separator := slices.Index(fields, "-")
	if separator == -1 || separator+1 >= len(fields) {
		return ""
	}
	return fields[separator+1]
}
