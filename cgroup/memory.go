package cgroup

import (
	"path"

	"github.com/coroot/coroot-node-agent/common"
)

const maxMemory = 1 << 62

type MemoryStat struct {
	RSS   uint64
	Cache uint64
	Limit uint64
}

func (cg *Cgroup) MemoryStat() (*MemoryStat, error) {
	if cg.Version == V1 {
		return cg.memoryStatV1()
	}
	return cg.memoryStatV2()
}

func (cg *Cgroup) memoryStatV1() (*MemoryStat, error) {
	vars, err := readVariablesFromFile(path.Join(cgRoot, "memory", cg.subsystems["memory"], "memory.stat"))
	if err != nil {
		return nil, err
	}
	limit, err := common.ReadUintFromFile(path.Join(cgRoot, "memory", cg.subsystems["memory"], "memory.limit_in_bytes"))
	if err != nil {
		return nil, err
	}
	if limit > maxMemory {
		limit = 0
	}
	// Note from https://www.kernel.org/doc/Documentation/cgroup-v1/memory.txt:
	// Only anonymous and swap cache memory is listed as part of 'rss' stat.
	//	This should not be confused with the true 'resident set size' or the
	//	amount of physical memory used by the cgroup.
	//	'rss + mapped_file" will give you resident set size of cgroup.
	//	(Note: file and shmem may be shared among other cgroups. In that case,
	//	 mapped_file is accounted only when the memory cgroup is owner of page
	//	 cache.)
	return &MemoryStat{
		RSS:   vars["rss"] + vars["mapped_file"],
		Cache: vars["cache"],
		Limit: limit,
	}, nil
}

func (cg *Cgroup) memoryStatV2() (*MemoryStat, error) {
	vars, err := readVariablesFromFile(path.Join(cgRoot, cg.subsystems[""], "memory.stat"))
	if err != nil {
		return nil, err
	}
	limit, _ := common.ReadUintFromFile(path.Join(cgRoot, cg.subsystems[""], "memory.max"))
	return &MemoryStat{
		RSS:   vars["anon"] + vars["file_mapped"],
		Cache: vars["file"],
		Limit: limit,
	}, nil
}
