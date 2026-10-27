package containers

import (
	"encoding/binary"
	"errors"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/coroot/coroot-node-agent/proc"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	ciliumMapsDir      = "/sys/fs/bpf/tc/globals"
	ciliumCt4MapName   = "cilium_ct4_global"
	ciliumCt6MapName   = "cilium_ct6_global"
	ciliumTupleService = 4
	ciliumProtoTCP     = 6
)

var (
	ciliumBackends4MapNames = []string{"cilium_lb4_backends_v3", "cilium_lb4_backends_v2"}
	ciliumBackends6MapNames = []string{"cilium_lb6_backends_v3", "cilium_lb6_backends_v2"}
)

type ciliumTupleKey4 struct {
	DestAddr   [4]byte
	SourceAddr [4]byte
	DestPort   [2]byte
	SourcePort [2]byte
	NextHeader uint8
	Flags      uint8
}

type ciliumTupleKey6 struct {
	DestAddr   [16]byte
	SourceAddr [16]byte
	DestPort   [2]byte
	SourcePort [2]byte
	NextHeader uint8
	Flags      uint8
}

type ciliumCtEntry struct {
	Reserved0        uint64
	BackendID        uint64
	Packets          uint64
	Bytes            uint64
	Lifetime         uint32
	Flags            uint16
	RevNAT           uint16
	IfIndex          uint16
	TxFlagsSeen      uint8
	RxFlagsSeen      uint8
	SourceSecurityID uint32
	LastTxReport     uint32
	LastRxReport     uint32
}

type ciliumBackend4Value struct {
	Address [4]byte
	Port    [2]byte
	Proto   uint8
	Flags   uint8
}

type ciliumBackend4ValueV3 struct {
	Address   [4]byte
	Port      [2]byte
	Proto     uint8
	Flags     uint8
	ClusterID uint16
	Zone      uint8
	Pad       uint8
}

type ciliumBackend6Value struct {
	Address [16]byte
	Port    [2]byte
	Proto   uint8
	Flags   uint8
}

type ciliumBackend6ValueV3 struct {
	Address   [16]byte
	Port      [2]byte
	Proto     uint8
	Flags     uint8
	ClusterID uint16
	Zone      uint8
	Pad       uint8
}

type ciliumMap struct {
	name string
	m    *ebpf.Map
}

func openCiliumMap(names ...string) *ciliumMap {
	for _, name := range names {
		m, err := ebpf.LoadPinnedMap(proc.HostPath(filepath.Join(ciliumMapsDir, name)), &ebpf.LoadPinOptions{ReadOnly: true})
		if err != nil {
			klog.Infof("cilium ebpf-map %s: %v", name, err)
			continue
		}
		klog.Infoln("found cilium ebpf-map:", name)
		return &ciliumMap{name: name, m: m}
	}
	return nil
}

func (m *ciliumMap) lookup(key, value any) bool {
	err := m.m.Lookup(key, value)
	if err == nil {
		return true
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		klog.Warningf("cilium map %s lookup failed: %v", m.name, err)
	}
	return false
}

func (m *ciliumMap) valueSize() int {
	return int(m.m.ValueSize())
}

var (
	ciliumCt4       *ciliumMap
	ciliumCt6       *ciliumMap
	ciliumBackends4 *ciliumMap
	ciliumBackends6 *ciliumMap
)

func init() {
	ciliumCt4 = openCiliumMap(ciliumCt4MapName)
	ciliumCt6 = openCiliumMap(ciliumCt6MapName)
	ciliumBackends4 = openCiliumMap(ciliumBackends4MapNames...)
	ciliumBackends6 = openCiliumMap(ciliumBackends6MapNames...)
}

func lookupCiliumConntrackTable(src, dst netaddr.IPPort) *netaddr.IPPort {
	// IPv4-mapped IPv6 addresses are tracked by Cilium as IPv4
	srcIP, dstIP := src.IP().Unmap(), dst.IP().Unmap()
	switch {
	case srcIP.Is4() && dstIP.Is4():
		return lookupCilium4(srcIP, src.Port(), dstIP, dst.Port())
	case srcIP.Is6() && dstIP.Is6():
		return lookupCilium6(srcIP, src.Port(), dstIP, dst.Port())
	}
	return nil
}

func lookupCilium4(srcIP netaddr.IP, srcPort uint16, dstIP netaddr.IP, dstPort uint16) *netaddr.IPPort {
	if ciliumCt4 == nil || ciliumBackends4 == nil {
		return nil
	}
	key := ciliumTupleKey4{SourceAddr: srcIP.As4(), DestAddr: dstIP.As4(), NextHeader: ciliumProtoTCP, Flags: ciliumTupleService}
	binary.BigEndian.PutUint16(key.SourcePort[:], dstPort)
	binary.BigEndian.PutUint16(key.DestPort[:], srcPort)
	var entry ciliumCtEntry
	if !ciliumCt4.lookup(&key, &entry) {
		return nil
	}
	backendID := uint32(entry.BackendID)
	var addr [4]byte
	var port [2]byte
	switch ciliumBackends4.valueSize() {
	case binary.Size(ciliumBackend4Value{}):
		var b ciliumBackend4Value
		if !ciliumBackends4.lookup(&backendID, &b) {
			return nil
		}
		addr, port = b.Address, b.Port
	case binary.Size(ciliumBackend4ValueV3{}):
		var b ciliumBackend4ValueV3
		if !ciliumBackends4.lookup(&backendID, &b) {
			return nil
		}
		addr, port = b.Address, b.Port
	default:
		klog.Warningf("cilium map %s: unsupported value size %d", ciliumBackends4.name, ciliumBackends4.valueSize())
		return nil
	}
	res := netaddr.IPPortFrom(netaddr.IPFrom4(addr), binary.BigEndian.Uint16(port[:]))
	return &res
}

func lookupCilium6(srcIP netaddr.IP, srcPort uint16, dstIP netaddr.IP, dstPort uint16) *netaddr.IPPort {
	if ciliumCt6 == nil || ciliumBackends6 == nil {
		return nil
	}
	key := ciliumTupleKey6{SourceAddr: srcIP.As16(), DestAddr: dstIP.As16(), NextHeader: ciliumProtoTCP, Flags: ciliumTupleService}
	binary.BigEndian.PutUint16(key.SourcePort[:], dstPort)
	binary.BigEndian.PutUint16(key.DestPort[:], srcPort)
	var entry ciliumCtEntry
	if !ciliumCt6.lookup(&key, &entry) {
		return nil
	}
	backendID := uint32(entry.BackendID)
	var addr [16]byte
	var port [2]byte
	switch ciliumBackends6.valueSize() {
	case binary.Size(ciliumBackend6Value{}):
		var b ciliumBackend6Value
		if !ciliumBackends6.lookup(&backendID, &b) {
			return nil
		}
		addr, port = b.Address, b.Port
	case binary.Size(ciliumBackend6ValueV3{}):
		var b ciliumBackend6ValueV3
		if !ciliumBackends6.lookup(&backendID, &b) {
			return nil
		}
		addr, port = b.Address, b.Port
	default:
		klog.Warningf("cilium map %s: unsupported value size %d", ciliumBackends6.name, ciliumBackends6.valueSize())
		return nil
	}
	res := netaddr.IPPortFrom(netaddr.IPFrom16(addr), binary.BigEndian.Uint16(port[:]))
	return &res
}
