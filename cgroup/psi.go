package cgroup

import (
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/coroot/coroot-node-agent/common"
	"k8s.io/klog/v2"
)

type PSIStats struct {
	CPUSecondsSome    float64
	CPUSecondsFull    float64
	MemorySecondsSome float64
	MemorySecondsFull float64
	IOSecondsSome     float64
	IOSecondsFull     float64
}

type PressureTotals struct {
	SomeSecondsTotal float64
	FullSecondsTotal float64
}

func (cg *Cgroup) PSI() *PSIStats {
	if cg.subsystems[""] == "" {
		return nil
	}
	stats := &PSIStats{}
	for _, controller := range []string{"cpu", "memory", "io"} {
		p, err := cg.readPressure(controller)
		if err != nil {
			if !common.IsNotExist(err) {
				klog.Warningln(err)
			}
			return nil
		}
		switch controller {
		case "cpu":
			stats.CPUSecondsSome = p.SomeSecondsTotal
			stats.CPUSecondsFull = p.FullSecondsTotal
		case "memory":
			stats.MemorySecondsSome = p.SomeSecondsTotal
			stats.MemorySecondsFull = p.FullSecondsTotal
		case "io":
			stats.IOSecondsSome = p.SomeSecondsTotal
			stats.IOSecondsFull = p.FullSecondsTotal
		}
	}
	return stats
}

func (cg *Cgroup) readPressure(controller string) (*PressureTotals, error) {
	data, err := os.ReadFile(path.Join(cg2Root, cg.subsystems[""], controller+".pressure"))
	if err != nil {
		return nil, err
	}
	pressure := &PressureTotals{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		kind := parts[0]
		for _, p := range parts[1:] {
			if strings.HasPrefix(p, "total=") {
				vStr := strings.TrimPrefix(p, "total=")
				v, err := strconv.ParseUint(vStr, 10, 64)
				if err != nil {
					return nil, err
				}
				switch kind {
				case "some":
					pressure.SomeSecondsTotal = float64(v) / 1e6 // microseconds to seconds
				case "full":
					pressure.FullSecondsTotal = float64(v) / 1e6
				}
				break
			}
		}
	}
	return pressure, nil
}
