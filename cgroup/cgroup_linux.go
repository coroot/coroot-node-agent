package cgroup

import (
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	"runtime"
)

func init() {
	selfNs, err := netns.GetFromPath("/proc/self/ns/cgroup")
	if err != nil {
		klog.Exitln(err)
	}
	defer selfNs.Close()
	hostNs, err := netns.GetFromPath("/proc/1/ns/cgroup")
	if err != nil {
		klog.Exitln(err)
	}
	defer hostNs.Close()
	if selfNs.Equal(hostNs) {
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Setns(int(hostNs), unix.CLONE_NEWCGROUP); err != nil {
		klog.Exitln(err)
	}

	cg, err := NewFromProcessCgroupFile("/proc/self/cgroup")
	if err != nil {
		klog.Exitln(err)
	}
	baseCgroupPath = cg.Id

	if err := unix.Setns(int(selfNs), unix.CLONE_NEWCGROUP); err != nil {
		klog.Exitln(err)
	}
}
