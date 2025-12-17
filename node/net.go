package node

import (
	"regexp"
	"strings"

	"github.com/coroot/coroot-node-agent/proc"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

var netDeviceFilterRe = regexp.MustCompile(`^(en(p\d+)?p\d+s\d+(f\d+)?|eth\d+|eno\d+|ens\d+|em\d+|bond\d+|p\d+p\d+|enx[0-9a-f]+|br\d+|vmbr\d+)`)

func netDeviceFilter(name string) bool {
	return netDeviceFilterRe.MatchString(strings.ToLower(name))
}

type NetDeviceInfo struct {
	Name       string
	Up         float64
	IPPrefixes []netaddr.IPPrefix
	RxBytes    float64
	TxBytes    float64
	RxPackets  float64
	TxPackets  float64
}

func NetDevices() ([]NetDeviceInfo, error) {
	hostNs, err := proc.GetHostNetNs()
	if err != nil {
		return nil, err
	}
	defer hostNs.Close()
	h, err := netlink.NewHandleAt(hostNs)
	if err != nil {
		return nil, err
	}
	defer h.Delete()
	links, err := h.LinkList()
	if err != nil {
		return nil, err
	}
	var res []NetDeviceInfo
	for _, link := range links {
		attrs := link.Attrs()
		if !netDeviceFilter(attrs.Name) {
			continue
		}
		info := NetDeviceInfo{
			Name:      attrs.Name,
			RxBytes:   float64(attrs.Statistics.RxBytes),
			TxBytes:   float64(attrs.Statistics.TxBytes),
			RxPackets: float64(attrs.Statistics.RxPackets),
			TxPackets: float64(attrs.Statistics.TxPackets),
		}
		if attrs.OperState == netlink.OperUp {
			info.Up = 1
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
			if prefix, ok := netaddr.FromStdIPNet(addr.IPNet); ok {
				info.IPPrefixes = append(info.IPPrefixes, prefix)
			}
		}
		res = append(res, info)
	}
	return res, nil
}
