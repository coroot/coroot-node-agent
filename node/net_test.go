package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetDeviceFilter(t *testing.T) {
	assert.True(t, netDeviceFilter("eth0"))
	assert.True(t, netDeviceFilter("eth0@if699"))
	assert.True(t, netDeviceFilter("enp2s0"))
	assert.True(t, netDeviceFilter("bond0"))
	assert.True(t, netDeviceFilter("ens1"))
	assert.True(t, netDeviceFilter("p1p1"))
	assert.True(t, netDeviceFilter("eno2"))
	assert.True(t, netDeviceFilter("em1"))
	assert.True(t, netDeviceFilter("enx78e7d1ea46da"))
	assert.True(t, netDeviceFilter("enP4p65s0"))
	assert.True(t, netDeviceFilter("enP2p33s0"))
	assert.True(t, netDeviceFilter("enX0"))

	assert.False(t, netDeviceFilter("dummy0"))
	assert.False(t, netDeviceFilter("docker0"))
	assert.False(t, netDeviceFilter("kube-ipvs0"))
	assert.False(t, netDeviceFilter("veth1b0c947@if2"))
	assert.False(t, netDeviceFilter("flannel.1"))
	assert.False(t, netDeviceFilter("cni0"))
	assert.False(t, netDeviceFilter("lxc00aa@if698"))
}
