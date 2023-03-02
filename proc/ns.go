package proc

import (
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"runtime"
)

func GetNetNs(pid uint32) (netns.NsHandle, error) {
	return netns.GetFromPid(int(pid))
}

func GetSelfNetNs() (netns.NsHandle, error) {
	return netns.Get()
}

func GetHostNetNs() (netns.NsHandle, error) {
	return GetNetNs(1)
}

func ExecuteInNetNs(newNs, curNs netns.NsHandle, f func() error) error {
	if newNs.Equal(curNs) {
		return f()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := netns.Set(newNs); err != nil {
		return err
	}

	errF := f()

	if err := netns.Set(curNs); err != nil {
		return err
	}

	return errF
}

func GetNsIps(ns netns.NsHandle) ([]netaddr.IP, error) {
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil, err
	}
	defer h.Delete()

	links, err := h.LinkList()
	if err != nil {
		return nil, err
	}
	var res []netaddr.IP
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.OperState == netlink.OperDown {
			continue
		}
		addrs, err := h.AddrList(link, unix.AF_UNSPEC)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip := addr.IP
			if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if ip, ok := netaddr.FromStdIP(ip); ok {
				res = append(res, ip)
			}
		}
	}
	return res, nil
}
