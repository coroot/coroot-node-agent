package cgroup

import (
	"path"
)

const maxMemory = 1 << 62

type MemoryStat struct {
	RSS   uint64
	Cache uint64
}

func (cg *Cgroup) MemoryStat() (MemoryStat, error) {
	vars, err := readVariablesFromFile(path.Join(cgRoot, "memory", cg.subsystems["memory"], "memory.stat"))
	if err != nil {
		return MemoryStat{}, err
	}
	// Note from https://www.kernel.org/doc/Documentation/cgroup-v1/memory.txt:
	// Only anonymous and swap cache memory is listed as part of 'rss' stat.
	//	This should not be confused with the true 'resident set size' or the
	//	amount of physical memory used by the cgroup.
	//	'rss + mapped_file" will give you resident set size of cgroup.
	//	(Note: file and shmem may be shared among other cgroups. In that case,
	//	 mapped_file is accounted only when the memory cgroup is owner of page
	//	 cache.)
	return MemoryStat{
		RSS:   vars["rss"] + vars["mapped_file"],
		Cache: vars["cache"],
	}, nil
}

func (cg *Cgroup) MemoryLimitBytes() (uint64, error) {
	limit, err := readUintFromFile(path.Join(cgRoot, "memory", cg.subsystems["memory"], "memory.limit_in_bytes"))
	if err != nil {
		return 0, err
	}
	if limit > maxMemory {
		return 0, nil
	}
	return limit, nil
}
