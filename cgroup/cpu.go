package cgroup

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/coroot/coroot-node-agent/common"
)

type CPUStat struct {
	UsageSeconds         float64
	ThrottledTimeSeconds float64
	LimitCores           float64
}

func (cg Cgroup) CpuStat() *CPUStat {
	cpu, cpuacct := cg.subsystems["cpu"], cg.subsystems["cpuacct"]
	if cpu == "" || cpuacct == "" {
		st, _ := cg.cpuStatV2()
		return st
	}
	st, _ := cg.cpuStatV1()
	return st
}

func (cg Cgroup) cpuStatV1() (*CPUStat, error) {
	if cg.subsystems["cpu"] == "" || cg.subsystems["cpuacct"] == "" {
		return nil, nil
	}
	throttling, err := readVariablesFromFile(path.Join(cgRoot, "cpu", cg.subsystems["cpu"], "cpu.stat"))
	if err != nil {
		return nil, err
	}
	usageNs, err := common.ReadIntFromFile(path.Join(cgRoot, "cpuacct", cg.subsystems["cpuacct"], "cpuacct.usage"))
	if err != nil {
		return nil, err
	}
	periodUs, err := common.ReadIntFromFile(path.Join(cgRoot, "cpu", cg.subsystems["cpu"], "cpu.cfs_period_us"))
	if err != nil {
		return nil, err
	}
	quotaUs, err := common.ReadIntFromFile(path.Join(cgRoot, "cpu", cg.subsystems["cpu"], "cpu.cfs_quota_us"))
	if err != nil {
		return nil, err
	}
	res := &CPUStat{
		UsageSeconds:         float64(usageNs) / 1e9,
		ThrottledTimeSeconds: float64(throttling["throttled_time"]) / 1e9,
	}
	if quotaUs > 0 {
		res.LimitCores = float64(quotaUs) / float64(periodUs)
	}
	return res, nil
}

func (cg Cgroup) cpuStatV2() (*CPUStat, error) {
	if cg.subsystems[""] == "" {
		return nil, nil
	}
	vars, err := readVariablesFromFile(path.Join(cg2Root, cg.subsystems[""], "cpu.stat"))
	if err != nil {
		return nil, err
	}
	res := &CPUStat{
		UsageSeconds:         float64(vars["usage_usec"]) / 1e6,
		ThrottledTimeSeconds: float64(vars["throttled_usec"]) / 1e6,
	}
	if payload, err := os.ReadFile(path.Join(cg2Root, cg.subsystems[""], "cpu.max")); err == nil {
		data := strings.TrimSpace(string(payload))
		parts := strings.Fields(data)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid cpu.max payload: %s", data)
		}
		if parts[0] == "max" { //no limit
			return res, nil
		}
		quotaUs, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid quota value in cpu.max: %s", parts[0])
		}
		periodUs, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid period value in cpu.max: %s", parts[1])
		}
		if periodUs > 0 {
			res.LimitCores = float64(quotaUs) / float64(periodUs)
		}
	}
	return res, nil
}
