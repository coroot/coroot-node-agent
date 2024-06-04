package common

import (
	"strconv"
	"strings"

	"github.com/coroot/coroot-node-agent/flags"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

var (
	ConnectionFilter = connectionFilter{
		whitelist: map[string]netaddr.IPPrefix{},
	}
	PortFilter *portFilter
)

func init() {
	klog.Infoln("whitelisted public IPs:", *flags.ExternalNetworksWhitelist)
	for _, prefix := range *flags.ExternalNetworksWhitelist {
		if prefix == "" {
			continue
		}
		p, err := netaddr.ParseIPPrefix(prefix)
		if err != nil {
			klog.Fatalf("invalid network %s: %s", prefix, err)
		}
		ConnectionFilter.WhitelistPrefix(p)
	}
	if r := flags.EphemeralPortRange; r != nil && *r != "" {
		klog.Infoln("ephemeral-port-range:", *r)
		parts := strings.Split(*r, "-")
		if len(parts) != 2 {
			klog.Fatalf("invalid port range: %s", *r)
		}
		from, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			klog.Fatalf("invalid port range: %s", *r)
		}
		to, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			klog.Fatalf("invalid port range: %s", *r)
		}
		if from > to {
			klog.Fatalf("invalid port range: %s", *r)
		}
		PortFilter = &portFilter{
			from: uint16(from),
			to:   uint16(to),
		}
	}
}

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

type connectionFilter struct {
	whitelist map[string]netaddr.IPPrefix
}

func (f connectionFilter) WhitelistIP(ip netaddr.IP) {
	var bits uint8 = 32
	if ip.Is6() {
		bits = 128
	}
	f.WhitelistPrefix(netaddr.IPPrefixFrom(ip, bits))
}

func (f connectionFilter) WhitelistPrefix(p netaddr.IPPrefix) {
	if _, ok := f.whitelist[p.String()]; ok {
		return
	}
	f.whitelist[p.String()] = p
}

func (f connectionFilter) ShouldBeSkipped(dst, actualDst netaddr.IP) bool {
	if IsIpPrivate(dst) || dst.IsLoopback() {
		return false
	}
	for _, prefix := range f.whitelist {
		if prefix.Contains(dst) {
			return false
		}
	}
	if IsIpPrivate(actualDst) || actualDst.IsLoopback() {
		f.WhitelistIP(dst)
		return false
	}
	for _, prefix := range f.whitelist {
		if prefix.Contains(actualDst) {
			f.WhitelistIP(dst)
			return false
		}
	}
	return true
}

type portFilter struct {
	from uint16
	to   uint16
}

func (f *portFilter) ShouldBeSkipped(port uint16) bool {
	if f == nil {
		return false
	}
	return port >= f.from && port <= f.to
}
