package common

import (
	"inet.af/netaddr"
)

func IsIpPrivate(ip netaddr.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	if ip.Is4() {
		parts := ip.As4()
		return parts[0] == 100 && parts[1]&0xc0 == 64 // 100.64.0.0/10
	}
	return false
}
