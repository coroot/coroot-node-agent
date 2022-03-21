package cgroup

import (
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
)

func TestCgroup_MemoryStat(t *testing.T) {
	cgRoot = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	stat, err := cg.MemoryStat()
	assert.Nil(t, err)
	assert.Equal(t, uint64(0), stat.Limit)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	stat, err = cg.MemoryStat()
	assert.Nil(t, err)
	assert.Equal(t, uint64(14775123968), stat.RSS)
	assert.Equal(t, uint64(3206844416), stat.Cache)
	assert.Equal(t, uint64(21474836480), stat.Limit)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/400/cgroup"))
	stat, err = cg.MemoryStat()
	assert.Nil(t, err)
	assert.Equal(t, uint64(48648192-1044480), stat.RSS)
	assert.Equal(t, uint64(1044480), stat.Cache)
	assert.Equal(t, uint64(0), stat.Limit)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/500/cgroup"))
	stat, err = cg.MemoryStat()
	assert.Nil(t, err)
	assert.Equal(t, uint64(131047424-50835456), stat.RSS)
	assert.Equal(t, uint64(50835456), stat.Cache)
	assert.Equal(t, uint64(4294967296), stat.Limit)

}
