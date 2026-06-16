//go:build windows

package node

import (
	"fmt"
	"net"
	"runtime"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

const (
	ioctlDiskPerformance = 0x00070020
	maxPhysicalDrives    = 64
)

var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = modkernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
)

func uptime(procRoot string) (float64, error) {
	return windows.DurationSinceBoot().Seconds(), nil
}

func cpuStat(procRoot string) (CpuStat, error) {
	var idle, kernel, user windows.Filetime
	r1, _, err := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r1 == 0 {
		if err != syscall.Errno(0) {
			return CpuStat{}, err
		}
		return CpuStat{}, syscall.EINVAL
	}

	idleSeconds := filetimeSeconds(idle)
	kernelSeconds := filetimeSeconds(kernel)
	if kernelSeconds >= idleSeconds {
		kernelSeconds -= idleSeconds
	}
	return CpuStat{
		TotalUsage: CpuUsage{
			User:   filetimeSeconds(user),
			System: kernelSeconds,
			Idle:   idleSeconds,
		},
		LogicalCores: runtime.NumCPU(),
	}, nil
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func memoryInfo(procRoot string) (MemoryStat, error) {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	r1, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if r1 == 0 {
		if err != syscall.Errno(0) {
			return MemoryStat{}, err
		}
		return MemoryStat{}, syscall.EINVAL
	}
	return MemoryStat{
		TotalBytes:     float64(status.TotalPhys),
		FreeBytes:      float64(status.AvailPhys),
		AvailableBytes: float64(status.AvailPhys),
	}, nil
}

type DevStat struct {
	Name             string
	MajorMinor       string
	ReadOps          float64
	WriteOps         float64
	BytesRead        float64
	BytesWritten     float64
	ReadTimeSeconds  float64
	WriteTimeSeconds float64
	IoTimeSeconds    float64
}

type Disks struct {
	devices []DevStat
	byName  map[string]DevStat
}

func (disks *Disks) BlockDevices() []DevStat {
	res := append([]DevStat(nil), disks.devices...)
	sort.Slice(res, func(i, j int) bool {
		return res[i].Name < res[j].Name
	})
	return res
}

func (disks *Disks) GetParentBlockDevice(majorMinor string) *DevStat {
	if disks == nil {
		return nil
	}
	dev, ok := disks.byName[majorMinor]
	if !ok {
		return nil
	}
	return &dev
}

type diskPerformance struct {
	BytesRead           int64
	BytesWritten        int64
	ReadTime            int64
	WriteTime           int64
	IdleTime            int64
	ReadCount           uint32
	WriteCount          uint32
	QueueDepth          uint32
	SplitCount          uint32
	QueryTime           int64
	StorageDeviceNumber uint32
	StorageManagerName  [8]uint16
}

func GetDisks() (*Disks, error) {
	disks := &Disks{byName: map[string]DevStat{}}
	for i := 0; i < maxPhysicalDrives; i++ {
		name := fmt.Sprintf("PhysicalDrive%d", i)
		stat, ok, err := diskStat(name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		disks.devices = append(disks.devices, stat)
		disks.byName[stat.MajorMinor] = stat
	}
	return disks, nil
}

func diskStat(name string) (DevStat, bool, error) {
	path, err := windows.UTF16PtrFromString(`\\.\` + name)
	if err != nil {
		return DevStat{}, false, err
	}
	handle, err := windows.CreateFile(
		path,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		if isMissingDisk(err) {
			return DevStat{}, false, nil
		}
		if err == windows.ERROR_ACCESS_DENIED {
			return DevStat{}, false, nil
		}
		return DevStat{}, false, err
	}
	defer windows.CloseHandle(handle)

	var perf diskPerformance
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		handle,
		ioctlDiskPerformance,
		nil,
		0,
		(*byte)(unsafe.Pointer(&perf)),
		uint32(unsafe.Sizeof(perf)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		if err == windows.ERROR_INVALID_FUNCTION || err == windows.ERROR_NOT_SUPPORTED || err == windows.ERROR_ACCESS_DENIED {
			return DevStat{}, false, nil
		}
		return DevStat{}, false, err
	}
	return DevStat{
		Name:             name,
		MajorMinor:       name,
		ReadOps:          float64(perf.ReadCount),
		WriteOps:         float64(perf.WriteCount),
		BytesRead:        float64(perf.BytesRead),
		BytesWritten:     float64(perf.BytesWritten),
		ReadTimeSeconds:  windowsCounterSeconds(perf.ReadTime),
		WriteTimeSeconds: windowsCounterSeconds(perf.WriteTime),
		IoTimeSeconds:    windowsCounterSeconds(perf.ReadTime + perf.WriteTime),
	}, true, nil
}

func isMissingDisk(err error) bool {
	return err == windows.ERROR_FILE_NOT_FOUND ||
		err == windows.ERROR_PATH_NOT_FOUND ||
		err == windows.ERROR_INVALID_NAME
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
	adapters, buffer, err := getAdaptersAddresses()
	if err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(buffer)
	var res []NetDeviceInfo
	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		if adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		name := adapterName(adapter)
		if name == "" {
			continue
		}
		info := NetDeviceInfo{Name: name}
		if adapter.OperStatus == windows.IfOperStatusUp {
			info.Up = 1
		}
		row, err := interfaceRow(adapter)
		if err == nil {
			info.RxBytes = float64(row.InOctets)
			info.TxBytes = float64(row.OutOctets)
			info.RxPackets = float64(row.InUcastPkts + row.InNUcastPkts)
			info.TxPackets = float64(row.OutUcastPkts + row.OutNUcastPkts)
			if row.OperStatus == windows.IfOperStatusUp {
				info.Up = 1
			}
		} else {
			index := adapter.IfIndex
			if index == 0 {
				index = adapter.Ipv6IfIndex
			}
			legacy, legacyErr := legacyInterfaceRow(index)
			if legacyErr != nil {
				return nil, legacyErr
			}
			info.RxBytes = float64(legacy.InOctets)
			info.TxBytes = float64(legacy.OutOctets)
			info.RxPackets = float64(legacy.InUcastPkts + legacy.InNUcastPkts)
			info.TxPackets = float64(legacy.OutUcastPkts + legacy.OutNUcastPkts)
			if legacy.OperStatus == windows.IfOperStatusUp {
				info.Up = 1
			}
		}
		for addr := adapter.FirstUnicastAddress; addr != nil; addr = addr.Next {
			ip := addr.Address.IP()
			if skipInterfaceIP(ip) {
				continue
			}
			na, ok := netaddr.FromStdIP(ip)
			if !ok {
				continue
			}
			info.IPPrefixes = append(info.IPPrefixes, netaddr.IPPrefixFrom(na, addr.OnLinkPrefixLength))
		}
		res = append(res, info)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Name < res[j].Name
	})
	return res, nil
}

func getAdaptersAddresses() (*windows.IpAdapterAddresses, []byte, error) {
	size := uint32(15 * 1024)
	for {
		buffer := make([]byte, size)
		adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_PREFIX|windows.GAA_FLAG_INCLUDE_ALL_INTERFACES|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0,
			adapters,
			&size,
		)
		if err == nil {
			return adapters, buffer, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, nil, err
		}
	}
}

func interfaceRow(adapter *windows.IpAdapterAddresses) (windows.MibIfRow2, error) {
	row := windows.MibIfRow2{
		InterfaceLuid:  adapter.Luid,
		InterfaceIndex: adapter.IfIndex,
	}
	if row.InterfaceIndex == 0 {
		row.InterfaceIndex = adapter.Ipv6IfIndex
	}
	err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row)
	return row, err
}

func legacyInterfaceRow(index uint32) (windows.MibIfRow, error) {
	row := windows.MibIfRow{Index: index}
	err := windows.GetIfEntry(&row)
	return row, err
}

func adapterName(adapter *windows.IpAdapterAddresses) string {
	if adapter.FriendlyName != nil {
		return windows.UTF16PtrToString(adapter.FriendlyName)
	}
	if adapter.AdapterName != nil {
		return bytePtrToString(adapter.AdapterName)
	}
	return ""
}

func bytePtrToString(p *byte) string {
	if p == nil {
		return ""
	}
	var buf []byte
	for i := uintptr(0); ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

func skipInterfaceIP(ip net.IP) bool {
	return ip == nil ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast()
}

func filetimeSeconds(ft windows.Filetime) float64 {
	v := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
	return float64(v) / 1e7
}

func windowsCounterSeconds(v int64) float64 {
	return float64(v) / 1e7
}
