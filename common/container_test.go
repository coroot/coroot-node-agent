package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerFilter(t *testing.T) {
	f, err := newContainerFilter(nil, nil)
	require.NoError(t, err)

	assert.False(t, f.ShouldBeSkipped("/k8s/default/pod/container"))

	f, err = newContainerFilter([]string{`.+/default/.+`}, nil)
	require.NoError(t, err)
	assert.False(t, f.ShouldBeSkipped("/k8s/default/pod/container"))
	assert.True(t, f.ShouldBeSkipped("/k8s/default1/pod/container"))

	f, err = newContainerFilter(nil, []string{`.+/jobs/.+`})
	require.NoError(t, err)
	assert.False(t, f.ShouldBeSkipped("/k8s/default/pod/container"))
	assert.True(t, f.ShouldBeSkipped("/k8s/jobs/pod/container"))

	f, err = newContainerFilter([]string{`.+`}, []string{`.+/jobs/.+`})
	require.NoError(t, err)
	assert.False(t, f.ShouldBeSkipped("/k8s/default/pod/container"))
	assert.True(t, f.ShouldBeSkipped("/k8s/jobs/pod/container"))
}
