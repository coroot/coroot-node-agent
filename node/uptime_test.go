package node

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNode_uptime(t *testing.T) {
	v, err := uptime("fixtures/proc")
	assert.Nil(t, err)
	assert.Equal(t, 2659150.03, v)
}
