//go:build windows

package proc

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsListPidsIncludesCurrentProcess(t *testing.T) {
	pids, err := ListPids()
	if err != nil {
		t.Fatalf("ListPids failed: %v", err)
	}
	current := windows.GetCurrentProcessId()
	for _, pid := range pids {
		if pid == current {
			return
		}
	}
	t.Fatalf("current pid %d not found in %v", current, pids)
}

func TestWindowsGetCmdlineUsesProcessImagePath(t *testing.T) {
	cmdline := GetCmdline(windows.GetCurrentProcessId())
	if len(cmdline) == 0 {
		t.Fatal("GetCmdline returned empty image path for current process")
	}
}
