package cgroup

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFromProcessCgroupFile(t *testing.T) {
	cg, err := NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/system.slice/docker.service", cg.Id)
	assert.Equal(t, "/system.slice/docker.service", cg.ContainerId)
	assert.Equal(t, ContainerTypeSystemdService, cg.ContainerType)

	assert.Equal(t,
		map[string]string{
			"blkio":        "/system.slice/docker.service",
			"cpu":          "/system.slice/docker.service",
			"cpuacct":      "/system.slice/docker.service",
			"devices":      "/system.slice/docker.service",
			"memory":       "/system.slice/docker.service",
			"name=systemd": "/system.slice/docker.service",
			"pids":         "/system.slice/docker.service",
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

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/400/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8712f785_1a3e_41ec_a00b_e2dcc77431cb.slice/docker-73051af271105c07e1f493b34856a77e665e3b0b4fc72f76c807dfbffeb881bd.scope", cg.Id)
	assert.Equal(t, "73051af271105c07e1f493b34856a77e665e3b0b4fc72f76c807dfbffeb881bd", cg.ContainerId)
	assert.Equal(t, ContainerTypeDocker, cg.ContainerType)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/600/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/system.slice/springboot.service", cg.Id)
	assert.Equal(t, "/system.slice/springboot.service", cg.ContainerId)
	assert.Equal(t, ContainerTypeSystemdService, cg.ContainerType)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/700/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/podruntime/runtime", cg.Id)
	assert.Equal(t, "/talos/runtime", cg.ContainerId)
	assert.Equal(t, ContainerTypeTalosRuntime, cg.ContainerType)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/800/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/system.slice/docker-cf87ba651579c9231db817909e7865e5747bd7abcac0c57ce23cf4abbaee046b.scope", cg.Id)
	assert.Equal(t, "cf87ba651579c9231db817909e7865e5747bd7abcac0c57ce23cf4abbaee046b", cg.ContainerId)
	assert.Equal(t, ContainerTypeDocker, cg.ContainerType)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/900/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/system.slice/python-app.service", cg.Id)
	assert.Equal(t, "/system.slice/python-app.service", cg.ContainerId)
	assert.Equal(t, ContainerTypeSystemdService, cg.ContainerType)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/2000/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/kubepods/burstable/pod8833712d-6e69-4f5c-95f3-aebd020ce2e7/95cbe853416f52d927dec41f1406dd75015ea131244a1ca875a7cd4ebe927ac8", cg.Id)
	assert.Equal(t, "95cbe853416f52d927dec41f1406dd75015ea131244a1ca875a7cd4ebe927ac8", cg.ContainerId)
	assert.Equal(t, ContainerTypeDocker, cg.ContainerType)

	baseCgroupPath = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podc83d0428_58af_41eb_8dba_b9e6eddffe7b.slice/docker-0e612005fd07e7f47e2cd07df99a2b4e909446814d71d0b5e4efc7159dd51252.scope"
	defer func() {
		baseCgroupPath = ""
	}()
	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/500/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/system.slice/docker-ba7b10d15d16e10e3de7a2dcd408a3d971169ae303f46cfad4c5453c6326fee2.scope", cg.Id)
	assert.Equal(t, "ba7b10d15d16e10e3de7a2dcd408a3d971169ae303f46cfad4c5453c6326fee2", cg.ContainerId)
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

	typ, id, err = containerByCgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2942c55e_c9cb_428a_93f4_eaf89c1f3ce0.slice/crio-49f9e8e5395d57c1083996c09e2e6f042d5fe1ec0310facab32f94912b35ce59.scope")
	as.Equal(typ, ContainerTypeCrio)
	as.Equal("49f9e8e5395d57c1083996c09e2e6f042d5fe1ec0310facab32f94912b35ce59", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podea19ff5d_943a_4466_a07e_a71e9e50cc62.slice/crio-21572039dd8398ff8272b031fa5422a40165145ab37f2f8794e1e7f844fe8118.scope/container")
	as.Equal(typ, ContainerTypeCrio)
	as.Equal("21572039dd8398ff8272b031fa5422a40165145ab37f2f8794e1e7f844fe8118", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3e61c214bc3ed9ff81e21474dd6cba17.slice/cri-containerd-c74b0f5062f0bc726cae1e9369ad4a95deed6b298d247f0407475adb23fa3190")
	as.Equal(typ, ContainerTypeContainerd)
	as.Equal("c74b0f5062f0bc726cae1e9369ad4a95deed6b298d247f0407475adb23fa3190", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/system.slice/system-serial\\x2dgetty.slice")
	as.Equal(typ, ContainerTypeSystemdService)
	as.Equal("/system.slice/system-serial-getty.slice", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/runtime.slice/kubelet.service")
	as.Equal(typ, ContainerTypeSystemdService)
	as.Equal("/runtime.slice/kubelet.service", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/reserved.slice/kubelet.service")
	as.Equal(typ, ContainerTypeSystemdService)
	as.Equal("/reserved.slice/kubelet.service", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/system.slice/system-postgresql.slice/postgresql@9.4-main.service")
	as.Equal(typ, ContainerTypeSystemdService)
	as.Equal("/system.slice/system-postgresql.slice", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/system.slice/containerd.service/kubepods-burstable-pod4ed02c0b_0df8_4d14_a30e_fd589ee4143a.slice:cri-containerd:d4a9f9195eaf7e4a729f24151101e1de61f1398677e7b82acfb936dff0b4ce55")
	as.Equal(typ, ContainerTypeContainerd)
	as.Equal("d4a9f9195eaf7e4a729f24151101e1de61f1398677e7b82acfb936dff0b4ce55", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/podruntime/kubelet")
	as.Equal(typ, ContainerTypeTalosRuntime)
	as.Equal("/talos/kubelet", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/system/dashboard")
	as.Equal(typ, ContainerTypeTalosRuntime)
	as.Equal("/talos/dashboard", id)
	as.Nil(err)

	typ, id, err = containerByCgroup("/init")
	as.Equal(typ, ContainerTypeTalosRuntime)
	as.Equal("/talos/init", id)
	as.Nil(err)
}
