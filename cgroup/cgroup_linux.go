package cgroup

import (
	"os"
	"path"
	"runtime"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
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
	if !selfNs.Equal(hostNs) {
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
	}
	if _, err := os.Stat(path.Join(cgRoot, "unified")); err == nil {
		cg2Root = path.Join(cgRoot, "unified")
	}
	klog.Infoln("cgroup v2 root is", cg2Root)
	return nil
}
