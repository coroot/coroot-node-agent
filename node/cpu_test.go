package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNode_cpu(t *testing.T) {
	usage, err := cpuStat("fixtures/proc")

	assert.Nil(t, err)
	//cpu  22246621850 266246696 6211649668 51164293943 1715028476 0 3050509822 0 0 0
	assert.Equal(t,
		CpuStat{
			TotalUsage: CpuUsage{
				User:    222466218.50,
				Nice:    2662466.96,
				System:  62116496.68,
				Idle:    511642939.43,
				IoWait:  17150284.76,
				Irq:     0,
				SoftIrq: 30505098.22,
				Steal:   0,
			},
			LogicalCores: 16,
		},
		usage)
}
