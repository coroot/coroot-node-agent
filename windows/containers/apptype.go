//go:build windows

package containers

import (
	"path/filepath"
	"strings"

	"github.com/coroot/coroot-node-agent/apptype"
	"github.com/shirou/gopsutil/v4/process"
)

func guessApplicationType(pid uint32) string {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return ""
	}
	exe, err := p.Name()
	if err != nil || exe == "" {
		return ""
	}
	exe = strings.TrimSuffix(strings.ToLower(filepath.Base(exe)), ".exe")
	if t := apptype.GuessByCmdline([]byte(exe)); t != "" {
		return t
	}
	if t := apptype.GuessByExe(exe); t != "" {
		return t
	}
	return ""
}
