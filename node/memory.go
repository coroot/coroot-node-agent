package node

import (
	"io/ioutil"
	"k8s.io/klog/v2"
	"path"
	"strconv"
	"strings"
)

func memoryInfo(procRoot string) (MemoryStat, error) {
	mem := MemoryStat{}

	data, err := ioutil.ReadFile(path.Join(procRoot, "meminfo"))
	if err != nil {
		return mem, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		mul := float64(1)
		if len(parts) == 3 && parts[2] == "kB" {
			mul = 1000
		}
		v, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			klog.Warningln("broken meminfo line:", line)
		}
		switch parts[0] {
		case "MemTotal:":
			mem.TotalBytes = v * mul
		case "MemFree:":
			mem.FreeBytes = v * mul
		case "MemAvailable:":
			mem.AvailableBytes = v * mul
		case "Cached:":
			mem.CachedBytes = v * mul
		}
	}
	return mem, nil
}
