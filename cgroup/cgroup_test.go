package cgroup

import (
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
)

func TestNewFromProcessCgroupFile(t *testing.T) {
	cg, err := NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/system.slice/ssh.service", cg.Id)
	assert.Equal(t, "/system.slice/ssh.service", cg.ContainerId)
	assert.Equal(t, ContainerTypeSystemdService, cg.ContainerType)

	assert.Equal(t,
		map[string]string{
			"blkio":        "/system.slice/ssh.service",
			"cpu":          "/system.slice/ssh.service",
			"cpuacct":      "/system.slice/ssh.service",
			"cpuset":       "/",
			"devices":      "/system.slice/ssh.service",
			"freezer":      "/",
			"hugetlb":      "/",
			"memory":       "/system.slice/ssh.service",
			"name=systemd": "/system.slice/ssh.service",
			"net_cls":      "/",
			"net_prio":     "/",
			"perf_event":   "/",
			"pids":         "/system.slice/ssh.service",
		},
		cg.subsystems,
	)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/docker/b43d92bf1e5c6f78bb9b7bc6f40721280299855ba692092716e3a1b6c0b86f3f", cg.Id)
	assert.Equal(t, "b43d92bf1e5c6f78bb9b7bc6f40721280299855ba692092716e3a1b6c0b86f3f", cg.ContainerId)
	assert.Equal(t, ContainerTypeDocker, cg.ContainerType)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/300/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/kubepods/burstable/pod6a4ce4a0-ba47-11ea-b2a7-0cc47ac5979e/17db96a24ae1e9dd57143e62b1cb0d2d35e693c65c774c7470e87b0572e07c1a", cg.Id)
	assert.Equal(t, "17db96a24ae1e9dd57143e62b1cb0d2d35e693c65c774c7470e87b0572e07c1a", cg.ContainerId)
	assert.Equal(t, ContainerTypeDocker, cg.ContainerType)

}

func TestContainerByCgroup(t *testing.T) {
	as := assert.New(t)

	typ, id, err := containerByCgroup("/kubepods/burstable/pod9729a196c4723b60ab401eaff722982d/d166c6190614efc91956b78e96d74c3fbc96ca8e91948c36de3bc5b0e7b27d48")
	as.Equal(typ, ContainerTypeDocker)
	as.Equal("d166c6190614efc91956b78e96d74c3fbc96ca8e91948c36de3bc5b0e7b27d48", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/kubepods/besteffort/pod0d08203e-255a-11e9-8cd9-0007cb0b2cc8/671a50f5d60566556912f61511d0ec9e4d5c78d53fbc4676727180438bbbbc55/kube-proxy")
	as.Equal(typ, ContainerTypeDocker)
	as.Equal("671a50f5d60566556912f61511d0ec9e4d5c78d53fbc4676727180438bbbbc55", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/kubepods/poda38c12e8-255a-11e9-8cd9-0007cb0b2cc8/32c562ed81a2622b37b80cb216859820ba51bd694f60ee4cf10d07a4011266f8")
	as.Equal(typ, ContainerTypeDocker)
	as.Equal("32c562ed81a2622b37b80cb216859820ba51bd694f60ee4cf10d07a4011266f8", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/docker/63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2d")
	as.Equal(typ, ContainerTypeDocker)
	as.Equal("63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2d", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/lxc/mysql-primary-db")
	as.Equal(typ, ContainerTypeLxc)
	as.Equal("mysql-primary-db", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/kubepods/poda48c12e8-255a-11e9-8cd9-0007cb0b2cc8/crio-63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2e")
	as.Equal(typ, ContainerTypeCrio)
	as.Equal("63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2e", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3e61c214bc3ed9ff81e21474dd6cba17.slice/cri-containerd-c74b0f5062f0bc726cae1e9369ad4a95deed6b298d247f0407475adb23fa3190")
	as.Equal(typ, ContainerTypeContainerd)
	as.Equal("c74b0f5062f0bc726cae1e9369ad4a95deed6b298d247f0407475adb23fa3190", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/system.slice/system-serial\\x2dgetty.slice")
	as.Equal(typ, ContainerTypeSystemdService)
	as.Equal("/system.slice/system-serial\\x2dgetty.slice", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/system.slice/system-postgresql.slice/postgresql@9.4-main.service")
	as.Equal(typ, ContainerTypeSystemdService)
	as.Equal("/system.slice/system-postgresql.slice", id)
	as.Nil(err)
}
