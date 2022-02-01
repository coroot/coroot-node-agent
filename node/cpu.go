package node

import (
	"io/ioutil"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const CLOCKS_PER_SEC = float64(100)

var (
	cpuCorePrefix = regexp.MustCompile(`cpu\d+`)
)

func cpuStat(procRoot string) (CpuStat, error) {
	stat := CpuStat{}
	data, err := ioutil.ReadFile(path.Join(procRoot, "stat"))
	if err != nil {
		return stat, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "cpu ") {
			parts := strings.Fields(line)
			if stat.TotalUsage.User, err = strconv.ParseFloat(parts[1], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.Nice, err = strconv.ParseFloat(parts[2], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.System, err = strconv.ParseFloat(parts[3], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.Idle, err = strconv.ParseFloat(parts[4], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.IoWait, err = strconv.ParseFloat(parts[5], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.Irq, err = strconv.ParseFloat(parts[6], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.SoftIrq, err = strconv.ParseFloat(parts[7], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.Steal, err = strconv.ParseFloat(parts[8], 64); err != nil {
				return stat, err
			}
		} else if cpuCorePrefix.MatchString(line) {
			stat.LogicalCores++
		}
	}
	stat.TotalUsage.User /= CLOCKS_PER_SEC
	stat.TotalUsage.Nice /= CLOCKS_PER_SEC
	stat.TotalUsage.System /= CLOCKS_PER_SEC
	stat.TotalUsage.Idle /= CLOCKS_PER_SEC
	stat.TotalUsage.IoWait /= CLOCKS_PER_SEC
	stat.TotalUsage.Irq /= CLOCKS_PER_SEC
	stat.TotalUsage.SoftIrq /= CLOCKS_PER_SEC
	stat.TotalUsage.Steal /= CLOCKS_PER_SEC
	return stat, nil
}
