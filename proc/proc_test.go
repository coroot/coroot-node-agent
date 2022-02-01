package proc

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
	"testing"
)

func init() {
	SetRoot("fixtures")
}

func TestListPids(t *testing.T) {
	res, err := ListPids()
	require.NoError(t, err)

	assert.Equal(t, []uint32{123}, res)
}

func TestGetMountInfo(t *testing.T) {
	res := GetMountInfo(123)
	assert.Equal(t, map[string]MountInfo{
		"3125": {MajorMinor: "259:2", MountPoint: "/dev/termination-log"},
		"3126": {MajorMinor: "259:2", MountPoint: "/bitnami/kafka"},
		"3127": {MajorMinor: "259:2", MountPoint: "/scripts/setup.sh"},
		"3128": {MajorMinor: "259:2", MountPoint: "/etc/resolv.conf"},
		"3129": {MajorMinor: "259:2", MountPoint: "/etc/hostname"},
		"3130": {MajorMinor: "259:2", MountPoint: "/etc/hosts"},
	}, res)
}

func TestGetFdInfo(t *testing.T) {
	res := GetFdInfo(123, 4)
	assert.Equal(t, FdInfo{
		MntId: "1965",
		Flags: int(0100002),
		Dest:  "/var/lib/postgresql/data/pg_wal/000000010000000000000001",
	}, *res)
}

func TestGetSockets(t *testing.T) {
	res, err := GetSockets(123)
	require.NoError(t, err)

	ipp := func(s string) netaddr.IPPort {
		res, err := netaddr.ParseIPPort(s)
		require.NoError(t, err)
		return res
	}

	assert.Equal(t, []Sock{
		{Inode: "8039432", SAddr: ipp("0.0.0.0:5432"), DAddr: ipp("0.0.0.0:0"), Listen: true},
		{Inode: "8134154", SAddr: ipp("172.17.0.3:5432"), DAddr: ipp("172.17.0.4:36332"), Listen: false},
		{Inode: "8039433", SAddr: ipp("[::]:5432"), DAddr: ipp("[::]:0"), Listen: true},
	}, res)
}
