//go:build windows

package containers

import (
	"path/filepath"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v4/disk"
	"golang.org/x/sys/windows"
)

func getProcessDiskAndMount(pid uint32) (device, mountPoint string) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", ""
	}
	exe := windows.UTF16ToString(buf[:size])

	vol := strings.ToUpper(filepath.VolumeName(exe))
	if len(vol) != 2 || vol[1] != ':' {
		return "", ""
	}
	return vol, vol + `\`
}

func getVolumeSpace(mountPoint string) (totalBytes, freeBytes uint64, ok bool) {
	if mountPoint == "" {
		return 0, 0, false
	}
	usage, err := disk.Usage(mountPoint)
	if err != nil {
		return 0, 0, false
	}
	return usage.Total, usage.Free, true
}
