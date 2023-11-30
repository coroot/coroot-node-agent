package cgroup

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCgroup_CpuStat(t *testing.T) {
	cgRoot = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	s, err := cg.CpuStat()
	assert.Nil(t, err)
	assert.Equal(t, 0., s.LimitCores)
	assert.Equal(t, 26778.913419246, s.UsageSeconds)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	s, err = cg.CpuStat()
	assert.Nil(t, err)
	assert.Equal(t, 1.5, s.LimitCores)
	assert.Equal(t, 254005.032764376, s.ThrottledTimeSeconds)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/400/cgroup"))
	s, err = cg.CpuStat()
	assert.Nil(t, err)
	assert.Equal(t, 0.1, s.LimitCores)
	assert.Equal(t, 0.363166, s.ThrottledTimeSeconds)
	assert.Equal(t, 3795.681254, s.UsageSeconds)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/500/cgroup"))
	s, err = cg.CpuStat()
	assert.Nil(t, err)
	assert.Equal(t, 0., s.LimitCores)
	assert.Equal(t, 0., s.ThrottledTimeSeconds)
	assert.Equal(t, 5531.521992, s.UsageSeconds)
}
