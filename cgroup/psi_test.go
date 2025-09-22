package cgroup

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCgroupPSI(t *testing.T) {
	cgRoot = "fixtures/cgroup"
	cg2Root = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/400/cgroup"))
	stat := cg.PSI()
	require.NotNil(t, stat)
	assert.Equal(t, float64(465907442)/1e6, stat.CPUSecondsSome)
	assert.Equal(t, float64(463529433)/1e6, stat.CPUSecondsFull)
	assert.Equal(t, float64(6937313991)/1e6, stat.MemorySecondsSome)
	assert.Equal(t, float64(6934649214)/1e6, stat.MemorySecondsFull)
	assert.Equal(t, float64(17657662684)/1e6, stat.IOSecondsSome)
	assert.Equal(t, float64(17636951020)/1e6, stat.IOSecondsFull)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	assert.Nil(t, cg.PSI())
}
