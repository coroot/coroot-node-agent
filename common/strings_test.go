package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateUtf8(t *testing.T) {
	assert.Equal(t, "ssss", TruncateUtf8("ssss", 10))
	assert.Equal(t, "ss", TruncateUtf8("ssss", 2))
	assert.Equal(t, "1", TruncateUtf8("1€€", 2))
	assert.Equal(t, "1€", TruncateUtf8("1€€", 4))
	assert.Equal(t, "", TruncateUtf8("€", 2))
}
