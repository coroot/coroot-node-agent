package proc

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

func init() {
	root = "fixtures"
}

func TestListPids(t *testing.T) {
	res, err := ListPids()
	require.NoError(t, err)
	sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
	assert.Equal(t, []uint32{123, 88451}, res)
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

func TestGetNsPid(t *testing.T) {
	nsPid, err := GetNsPid(123)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), nsPid)

	nsPid, err = GetNsPid(88451)
	require.NoError(t, err)
	assert.Equal(t, uint32(88451), nsPid)
}

func TestReadFds(t *testing.T) {
	fds, err := ReadFds(123)
	require.NoError(t, err)
	assert.Equal(t, []Fd{
		{Fd: 4, Dest: "/var/lib/postgresql/data/pg_wal/000000010000000000000001"},
		{Fd: 5, Dest: "socket:[321]", SocketInode: "321"},
	}, fds)
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
		{Inode: "11139979", SAddr: ipp("[fe80::48cb:8b57:3c30:e6ac]:8080"), DAddr: ipp("[::]:0"), Listen: true},
		{Inode: "11154515", SAddr: ipp("127.0.0.1:8081"), DAddr: ipp("[::]:0"), Listen: true},
	}, res)
}
