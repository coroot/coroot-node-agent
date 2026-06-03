//go:build windows

package containers

import (
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

func processStartTime(pid uint32) time.Time {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return time.Time{}
	}
	ms, err := p.CreateTime()
	if err != nil {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

func (c *Container) serviceStats() *Stats {
	live := make(map[uint32]Stats, len(c.PIDs))
	for _, pid := range c.PIDs {
		s, ok := processStats(pid)
		if !ok {
			continue
		}
		live[pid] = s
	}
	return c.counters.update(live)
}

func processStats(pid uint32) (Stats, bool) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return Stats{}, false
	}
	var s Stats
	if t, err := p.Times(); err == nil {
		s.CPUSeconds = t.User + t.System
	}
	if m, err := p.MemoryInfo(); err == nil {
		s.MemoryRSSBytes = m.RSS
	}
	if io, err := p.IOCounters(); err == nil {
		s.IOReadBytes = io.ReadBytes
		s.IOWriteBytes = io.WriteBytes
		s.IOReadOps = io.ReadCount
		s.IOWriteOps = io.WriteCount
	}
	return s, true
}

type counterState struct {
	total Stats
	prev  map[uint32]Stats
}

func (cs *counterState) update(live map[uint32]Stats) *Stats {
	next := make(map[uint32]Stats, len(live))
	cs.total.MemoryRSSBytes = 0
	for pid, cur := range live {
		if prev, ok := cs.prev[pid]; ok {
			cs.total.CPUSeconds += delta(cur.CPUSeconds, prev.CPUSeconds)
			cs.total.IOReadBytes += delta(cur.IOReadBytes, prev.IOReadBytes)
			cs.total.IOWriteBytes += delta(cur.IOWriteBytes, prev.IOWriteBytes)
			cs.total.IOReadOps += delta(cur.IOReadOps, prev.IOReadOps)
			cs.total.IOWriteOps += delta(cur.IOWriteOps, prev.IOWriteOps)
		}
		cs.total.MemoryRSSBytes += cur.MemoryRSSBytes
		next[pid] = cur
	}
	cs.prev = next
	return &cs.total
}

func delta[T float64 | uint64](cur, prev T) T {
	if cur < prev {
		return cur
	}
	return cur - prev
}

func processTrees() map[uint32][]uint32 {
	procs, err := process.Processes()
	if err != nil {
		return nil
	}
	children := make(map[uint32][]uint32, len(procs))
	pids := make([]uint32, 0, len(procs))
	for _, p := range procs {
		pid := uint32(p.Pid)
		pids = append(pids, pid)
		if ppid, err := p.Ppid(); err == nil {
			children[uint32(ppid)] = append(children[uint32(ppid)], pid)
		}
	}

	trees := make(map[uint32][]uint32, len(pids))
	for _, root := range pids {
		tree := []uint32{root}
		seen := map[uint32]bool{root: true}
		for i := 0; i < len(tree); i++ {
			for _, child := range children[tree[i]] {
				if !seen[child] {
					seen[child] = true
					tree = append(tree, child)
				}
			}
		}
		trees[root] = tree
	}
	return trees
}
