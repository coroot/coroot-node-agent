package node

import (
	"fmt"
	"unsafe"

	psnet "github.com/shirou/gopsutil/v4/net"
	"golang.org/x/sys/windows"
)

type netInterface struct {
	Name      string
	Up        bool
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
	IPs       []string
}

func getNetworkInterfaces() ([]netInterface, error) {
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, nil, &size)
	if err != nil && err != windows.ERROR_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("GetAdaptersAddresses sizing: %w", err)
	}

	buf := make([]byte, size)
	addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, addr, &size)
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	counters, err := psnet.IOCounters(true)
	if err != nil {
		return nil, fmt.Errorf("net.IOCounters: %w", err)
	}
	byName := make(map[string]psnet.IOCountersStat, len(counters))
	for _, c := range counters {
		byName[c.Name] = c
	}

	var result []netInterface
	for aa := addr; aa != nil; aa = aa.Next {
		if aa.IfType != 6 && aa.IfType != 71 {
			continue
		}

		iface := netInterface{
			Name: windows.UTF16PtrToString(aa.FriendlyName),
			Up:   aa.OperStatus == 1,
		}

		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip := ua.Address.IP(); ip != nil {
				iface.IPs = append(iface.IPs, ip.String())
			}
		}

		if c, ok := byName[iface.Name]; ok {
			iface.RxBytes = c.BytesRecv
			iface.TxBytes = c.BytesSent
			iface.RxPackets = c.PacketsRecv
			iface.TxPackets = c.PacketsSent
		}

		result = append(result, iface)
	}
	return result, nil
}
