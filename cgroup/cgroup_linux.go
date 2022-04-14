package cgroup

import (
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"runtime"
)

func Init() error {
	selfNs, err := netns.GetFromPath("/proc/self/ns/cgroup")
	if err != nil {
		return err
	}
	defer selfNs.Close()
	hostNs, err := netns.GetFromPath("/proc/1/ns/cgroup")
	if err != nil {
		return err
	}
	defer hostNs.Close()
	if selfNs.Equal(hostNs) {
		return nil
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Setns(int(hostNs), unix.CLONE_NEWCGROUP); err != nil {
		return err
	}

	cg, err := NewFromProcessCgroupFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	baseCgroupPath = cg.Id

	if err := unix.Setns(int(selfNs), unix.CLONE_NEWCGROUP); err != nil {
		return err
	}

	return nil
}
