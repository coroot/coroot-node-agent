package proc

import "syscall"

type FSStat struct {
	CapacityBytes uint64
	UsedBytes     uint64
	ReservedBytes uint64
}

func StatFS(dirPath string) (FSStat, error) {
	var s syscall.Statfs_t

	if err := syscall.Statfs(dirPath, &s); err != nil {
		return FSStat{}, err
	}
	res := FSStat{
		CapacityBytes: s.Blocks * uint64(s.Bsize),
		UsedBytes:     (s.Blocks - s.Bfree) * uint64(s.Bsize),
		ReservedBytes: (s.Bfree - s.Bavail) * uint64(s.Bsize),
	}
	return res, nil
}
