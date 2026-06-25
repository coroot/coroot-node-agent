//go:build windows

package containers

import (
	"net"
	"net/netip"
	"sync"
)

var (
	hostIPsOnce  sync.Once
	hostIPsCache []netip.Addr
)

func usableContainerIP(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast()
}

func expandListen(addr netip.Addr, port uint16, ips []netip.Addr) []string {
	if !addr.IsUnspecified() {
		return []string{netip.AddrPortFrom(addr, port).String()}
	}
	want4 := addr.Is4()
	var out []string
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.Is4() == want4 {
			out = append(out, netip.AddrPortFrom(ip, port).String())
		}
	}
	return out
}

func hostIPs() []netip.Addr {
	hostIPsOnce.Do(func() {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
				continue
			}
			hostIPsCache = append(hostIPsCache, ip)
		}
	})
	return hostIPsCache
}
