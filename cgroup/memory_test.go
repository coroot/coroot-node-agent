package cgroup

import (
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
)

func TestCgroup_MemoryStat(t *testing.T) {
	cgRoot = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	stat, err := cg.MemoryStat()
	assert.Nil(t, err)
	assert.Equal(t, uint64(14775123968), stat.RSS)
	assert.Equal(t, uint64(3206844416), stat.Cache)
}

func TestCgroup_MemoryLimitBytes(t *testing.T) {
	cgRoot = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	limit, err := cg.MemoryLimitBytes()
	assert.Nil(t, err)
	assert.Equal(t, uint64(0), limit)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	limit, err = cg.MemoryLimitBytes()
	assert.Nil(t, err)
	assert.Equal(t, uint64(21474836480), limit)

}
