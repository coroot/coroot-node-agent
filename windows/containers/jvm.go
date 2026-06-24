//go:build windows

package containers

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/coroot/coroot-node-agent/hsperf"
	"github.com/prometheus/client_golang/prometheus"
)

func collectJVMMetrics(ch chan<- prometheus.Metric, pids []uint32) {
	seen := map[string]bool{}
	for _, pid := range pids {
		file := findHsperfdataFile(pid)
		if file == "" {
			continue
		}
		jvm, ms, err := hsperf.Read(file)
		if err != nil || seen[jvm] {
			continue
		}
		seen[jvm] = true
		for _, m := range ms {
			ch <- m
		}
	}
}

func findHsperfdataFile(pid uint32) string {
	pidStr := strconv.Itoa(int(pid))
	patterns := []string{
		filepath.Join(os.TempDir(), "hsperfdata_*", pidStr),
		filepath.Join(`C:\Users\*\AppData\Local\Temp`, "hsperfdata_*", pidStr),
		filepath.Join(`C:\Windows\Temp`, "hsperfdata_*", pidStr),
	}
	for _, pattern := range patterns {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return matches[0]
		}
	}
	return ""
}
