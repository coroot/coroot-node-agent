package containers

import (
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
)

const maxClassifiedFds = 20000

type procCounters struct {
	voluntary, involuntary   float64
	minorFaults, majorFaults float64
}

// collectProcessResources reads /proc/<pid>/{status,stat,fd,limits} of the live processes of the container and exposes
// address space, shared memory, thread, scheduling, page fault and file descriptor series. Counters are accumulated from
// per-process deltas so that they stay monotonic when processes exit.
func (c *Container) collectProcessResources(ch chan<- prometheus.Metric) {
	if *flags.DisableProcessResourceMetrics || len(c.processes) == 0 {
		return
	}
	if c.procLast == nil {
		c.procLast = map[uint32]procCounters{}
	}
	var st proc.Status
	fds := map[string]float64{}
	ratio := 0.
	found := false
	for pid := range c.processes {
		s, err := proc.ReadStatus(pid)
		if err != nil {
			continue
		}
		found = true
		st.VmSizeBytes += s.VmSizeBytes
		st.VmDataBytes += s.VmDataBytes
		st.RssShmemBytes += s.RssShmemBytes

		cur := procCounters{voluntary: s.VoluntaryCtxSwitches, involuntary: s.InvoluntaryCtxSwitch}
		cur.minorFaults, cur.majorFaults, _ = proc.ReadFaults(pid)
		last, seen := c.procLast[pid]
		if !seen { // a process that started before the agent: count from now on
			last = cur
		}
		c.procTotal.voluntary += nonNegative(cur.voluntary - last.voluntary)
		c.procTotal.involuntary += nonNegative(cur.involuntary - last.involuntary)
		c.procTotal.minorFaults += nonNegative(cur.minorFaults - last.minorFaults)
		c.procTotal.majorFaults += nonNegative(cur.majorFaults - last.majorFaults)
		c.procLast[pid] = cur

		if f, err := proc.ReadFdStats(pid, maxClassifiedFds); err == nil {
			for kind, n := range f.ByKind {
				fds[kind] += n
			}
			if f.Limit > 0 && f.Total/f.Limit > ratio {
				ratio = f.Total / f.Limit
			}
		}
	}
	if !found {
		return
	}
	ch <- metrics.Gauge(metrics.MemoryVirtual, st.VmSizeBytes)
	ch <- metrics.Gauge(metrics.MemoryData, st.VmDataBytes)
	ch <- metrics.Gauge(metrics.MemoryShmem, st.RssShmemBytes)
	ch <- metrics.Counter(metrics.ContextSwitches, c.procTotal.voluntary, "voluntary")
	ch <- metrics.Counter(metrics.ContextSwitches, c.procTotal.involuntary, "involuntary")
	ch <- metrics.Counter(metrics.PageFaults, c.procTotal.minorFaults, "minor")
	ch <- metrics.Counter(metrics.PageFaults, c.procTotal.majorFaults, "major")
	for kind, n := range fds {
		ch <- metrics.Gauge(metrics.OpenFiles, n, kind)
	}
	ch <- metrics.Gauge(metrics.OpenFilesLimitRatio, ratio)
}

func nonNegative(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}
