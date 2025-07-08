package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetDeviceFilter(t *testing.T) {
	cases := map[string]bool{
		"eth0":            true,
		"eth0@if699":      true,
		"enp2s0":          true,
		"bond0":           true,
		"ens1":            true,
		"p1p1":            true,
		"eno2":            true,
		"em1":             true,
		"enx78e7d1ea46da": true,
		"enP4p65s0":       true,
		"enP2p33s0":       true,

		"dummy0":          false,
		"docker0":         false,
		"kube-ipvs0":      false,
		"veth1b0c947@if2": false,
		"flannel.1":       false,
		"cni0":            false,
		"lxc00aa@if698":   false,
	}

	for name, ok := range cases {
		assert.Equal(t, ok, netDeviceFilter(name), name)
	}
}
