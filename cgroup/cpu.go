package cgroup

import (
	"path"
)

type ThrottlingStat struct {
	Periods              uint64
	ThrottledPeriods     uint64
	ThrottledTimeSeconds float64
}

func (cg Cgroup) ThrottledTimeSeconds() (float64, error) {
	vars, err := readVariablesFromFile(path.Join(cgRoot, "cpu", cg.subsystems["cpu"], "cpu.stat"))
	if err != nil {
		return 0, err
	}
	return float64(vars["throttled_time"]) / 1e9, nil
}

func (cg Cgroup) CpuUsageSeconds() (float64, error) {
	usageNs, err := readIntFromFile(path.Join(cgRoot, "cpuacct", cg.subsystems["cpuacct"], "cpuacct.usage"))
	if err != nil {
		return 0, err
	}
	return float64(usageNs) / 1e9, err
}

func (cg Cgroup) CpuQuotaCores() (float64, error) {
	periodUs, err := readIntFromFile(path.Join(cgRoot, "cpu", cg.subsystems["cpu"], "cpu.cfs_period_us"))
	if err != nil {
		return -1, err
	}
	quotaUs, err := readIntFromFile(path.Join(cgRoot, "cpu", cg.subsystems["cpu"], "cpu.cfs_quota_us"))
	if err != nil {
		return -1, err
	}
	if quotaUs < 0 {
		return -1, nil
	}
	return float64(quotaUs) / float64(periodUs), nil
}
