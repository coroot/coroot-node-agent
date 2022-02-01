package cgroup

import (
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
)

func TestCgroup_CpuQuotaCores(t *testing.T) {
	cgRoot = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	quota, err := cg.CpuQuotaCores()
	assert.Nil(t, err)
	assert.Equal(t, -1., quota)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	quota, err = cg.CpuQuotaCores()
	assert.Nil(t, err)
	assert.Equal(t, 1.5, quota)
}

func TestCgroup_CpuUsageSeconds(t *testing.T) {
	cgRoot = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	usage, err := cg.CpuUsageSeconds()
	assert.Nil(t, err)
	assert.Equal(t, 26778.913419246, usage)
}

func TestCgroup_ThrottlingStat(t *testing.T) {
	cgRoot = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	tt, err := cg.ThrottledTimeSeconds()
	assert.Nil(t, err)
	assert.Equal(t, 254005.032764376, tt)
}
