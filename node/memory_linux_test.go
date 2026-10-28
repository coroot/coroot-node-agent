package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNode_memory(t *testing.T) {
	m, err := memoryInfo("fixtures/proc")
	assert.Nil(t, err)
	assert.Equal(t,
		MemoryStat{
			TotalBytes:     65871236 * 1024,
			FreeBytes:      7540732 * 1024,
			AvailableBytes: 23826720 * 1024,
			CachedBytes:    15878036 * 1024,
		},
		m,
	)
}
