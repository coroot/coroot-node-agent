package node

import (
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"regexp"
)

var includeNetDev = regexp.MustCompile(`^(enp\d+s\d+(f\d+)?|eth\d+|eno\d+|ens\d+)`)

type NetDeviceInfo struct {
	Name      string
	Up        float64
	Addresses []string
	RxBytes   float64
	TxBytes   float64
	RxPackets float64
	TxPackets float64
}

func netDevices() ([]NetDeviceInfo, error) {
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
		if !includeNetDev.MatchString(attrs.Name) {
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
			info.Addresses = append(info.Addresses, addr.IP.String())
		}
		res = append(res, info)
	}
	return res, nil

}
