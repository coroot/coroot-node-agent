package cgroup

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCgroup_MemoryStat(t *testing.T) {
	cgRoot = "fixtures/cgroup"
	cg2Root = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	stat := cg.MemoryStat()
	assert.Equal(t, uint64(0), stat.Limit)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	stat = cg.MemoryStat()
	assert.Equal(t, uint64(14775123968), stat.RSS)
	assert.Equal(t, uint64(3206844416), stat.Cache)
	assert.Equal(t, uint64(21474836480), stat.Limit)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/400/cgroup"))
	stat = cg.MemoryStat()
	assert.Equal(t, uint64(44892160+0), stat.RSS)
	assert.Equal(t, uint64(1044480), stat.Cache)
	assert.Equal(t, uint64(0), stat.Limit)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/500/cgroup"))
	stat = cg.MemoryStat()
	assert.Equal(t, uint64(75247616+4038656), stat.RSS)
	assert.Equal(t, uint64(50835456), stat.Cache)
	assert.Equal(t, uint64(4294967296), stat.Limit)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/550/cgroup"))
	stat = cg.MemoryStat()
	assert.Equal(t, uint64(3637248+2703360), stat.RSS)
	assert.Equal(t, uint64(7299072), stat.Cache)
	assert.Equal(t, uint64(0), stat.Limit)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/1000/cgroup"))
	stat, err := cg.memoryStatV1()
	assert.NoError(t, err)
	assert.Nil(t, stat)

}
