//go:build windows

package nettracer

import (
	"encoding/binary"
	"net"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpStateListen      = 2
	tcpStateEstablished = 5

	afInet  = 2
	afInet6 = 23

	tcpTableOwnerPidAll = 5
)

var (
	modIphlpapi                       = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable           = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetCurrentThreadCompartmentId = modIphlpapi.NewProc("GetCurrentThreadCompartmentId")
	procSetCurrentThreadCompartmentId = modIphlpapi.NewProc("SetCurrentThreadCompartmentId")
)

type tcpConn struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	State      uint32
	PID        uint32
}

func listTCPConnections() []tcpConn {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig := getCurrentCompartment()
	defer setCurrentCompartment(orig)

	seen := make(map[tcpConn]struct{})
	var out []tcpConn
	add := func(conns []tcpConn) {
		for _, c := range conns {
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	for _, cid := range listCompartments() {
		if !setCurrentCompartment(cid) || getCurrentCompartment() != cid {
			continue
		}
		add(parseTCPTable(afInet, getExtendedTCPTable(afInet)))
		add(parseTCPTable(afInet6, getExtendedTCPTable(afInet6)))
	}
	return out
}

func listCompartments() []uint32 {
	const flags = windows.GAA_FLAG_INCLUDE_ALL_COMPARTMENTS |
		windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER |
		windows.GAA_FLAG_SKIP_FRIENDLY_NAME
	size := uint32(16 * 1024)
	buf := make([]byte, size)
	get := func() error {
		return windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
	}
	err := get()
	if err == windows.ERROR_BUFFER_OVERFLOW {
		buf = make([]byte, size)
		err = get()
	}
	if err != nil {
		return []uint32{1} // fall back to the host default compartment
	}

	seen := map[uint32]bool{}
	var out []uint32
	for p := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); p != nil; p = p.Next {
		if !seen[p.CompartmentId] {
			seen[p.CompartmentId] = true
			out = append(out, p.CompartmentId)
		}
	}
	return out
}

func getCurrentCompartment() uint32 {
	r, _, _ := procGetCurrentThreadCompartmentId.Call()
	return uint32(r)
}

func setCurrentCompartment(id uint32) bool {
	r, _, _ := procSetCurrentThreadCompartmentId.Call(uintptr(id))
	return r == 0
}

func getExtendedTCPTable(af uint32) []byte {
	var size uint32
	r, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), tcpTableOwnerPidAll, 0)
	if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), tcpTableOwnerPidAll, 0)
	if r != 0 {
		return nil
	}
	return buf
}

func parseTCPTable(af uint32, buf []byte) []tcpConn {
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	rows := buf[4:]
	var rowSize int
	switch af {
	case afInet:
		rowSize = 24
	case afInet6:
		rowSize = 56
	default:
		return nil
	}
	out := make([]tcpConn, 0, n)
	for i := uint32(0); i < n; i++ {
		off := int(i) * rowSize
		if off+rowSize > len(rows) {
			break
		}
		r := rows[off : off+rowSize]
		var c tcpConn
		if af == afInet {
			c.State = binary.LittleEndian.Uint32(r[0:4])
			c.LocalIP = net.IP(r[4:8]).String()
			c.LocalPort = binary.BigEndian.Uint16(r[8:10])
			c.RemoteIP = net.IP(r[12:16]).String()
			c.RemotePort = binary.BigEndian.Uint16(r[16:18])
			c.PID = binary.LittleEndian.Uint32(r[20:24])
		} else {
			c.LocalIP = net.IP(r[0:16]).String()
			c.LocalPort = binary.BigEndian.Uint16(r[20:22])
			c.RemoteIP = net.IP(r[24:40]).String()
			c.RemotePort = binary.BigEndian.Uint16(r[44:46])
			c.State = binary.LittleEndian.Uint32(r[48:52])
			c.PID = binary.LittleEndian.Uint32(r[52:56])
		}
		out = append(out, c)
	}
	return out
}
