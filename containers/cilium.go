package containers

import (
	"path/filepath"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/coroot/coroot-node-agent/proc"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

var (
	ciliumCt4    *bpf.Map
	ciliumCt6    *bpf.Map
	backends4Map *bpf.Map
	backends6Map *bpf.Map
)

func init() {
	var err error

	ciliumCt4, err = bpf.OpenMap(proc.HostPath(filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, ctmap.MapNameTCP4Global)))
	if err != nil {
		klog.Infoln(err)
	} else {
		klog.Infoln("found cilium ebpf-map:", ctmap.MapNameTCP4Global)
	}
	ciliumCt6, err = bpf.OpenMap(proc.HostPath(filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, ctmap.MapNameTCP6Global)))
	if err != nil {
		klog.Infoln(err)
	} else {
		klog.Infoln("found cilium ebpf-map:", ctmap.MapNameTCP6Global)
	}
	for _, n := range []string{lbmap.Backend4MapV2Name, lbmap.Backend4MapV3Name} {
		backends4Map, err = bpf.OpenMap(proc.HostPath(filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, n)))
		if err != nil {
			klog.Infoln(err)
		} else {
			klog.Infoln("found cilium ebpf-map:", n)
			break
		}
	}
	for _, n := range []string{lbmap.Backend6MapV2Name, lbmap.Backend6MapV3Name} {
		backends6Map, err = bpf.OpenMap(proc.HostPath(filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, n)))
		if err != nil {
			klog.Infoln(err)
		} else {
			klog.Infoln("found cilium ebpf-map:", n)
			break
		}
	}

}

func lookupCiliumConntrackTable(src, dst netaddr.IPPort) *netaddr.IPPort {
	if src.IP().Is4() {
		return lookupCilium4(src, dst)
	}
	if src.IP().Is6() {
		return lookupCilium6(src, dst)
	}
	return nil
}

func lookupCilium4(src, dst netaddr.IPPort) *netaddr.IPPort {
	if ciliumCt4 == nil || backends4Map == nil {
		return nil
	}
	key := &ctmap.CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourcePort: dst.Port(),
				SourceAddr: src.IP().As4(),
				DestPort:   src.Port(),
				DestAddr:   dst.IP().As4(),
				NextHeader: u8proto.TCP,
				Flags:      ctmap.TUPLE_F_SERVICE,
			},
		},
	}
	v, err := ciliumCt4.Lookup(key.ToNetwork())
	if err != nil || v == nil {
		return nil
	}
	e := v.(*ctmap.CtEntry)

	// https://github.com/cilium/cilium/blob/v1.13.0/bpf/lib/common.h#L819
	// CtEntity.RxBytes stores `backend_id` if `e.Flags & TUPLE_F_SERVICE`
	backendId := e.RxBytes
	backendKey := lbmap.NewBackend4KeyV3(loadbalancer.BackendID(backendId))
	b, err := backends4Map.Lookup(backendKey)
	if err != nil || b == nil {
		return nil
	}
	var backend lbmap.BackendValue
	switch bv := b.(type) {
	case *lbmap.Backend4Value:
		backend = bv.ToHost()
	case *lbmap.Backend4ValueV3:
		backend = bv.ToHost()
	default:
		return nil
	}
	backendIP, _ := netaddr.FromStdIP(backend.GetAddress())
	res := netaddr.IPPortFrom(backendIP, backend.GetPort())
	return &res
}

func lookupCilium6(src, dst netaddr.IPPort) *netaddr.IPPort {
	if ciliumCt6 == nil || backends6Map == nil {
		return nil
	}
	key := &ctmap.CtKey6Global{
		TupleKey6Global: tuple.TupleKey6Global{
			TupleKey6: tuple.TupleKey6{
				SourcePort: dst.Port(),
				SourceAddr: src.IP().As16(),
				DestPort:   src.Port(),
				DestAddr:   dst.IP().As16(),
				NextHeader: u8proto.TCP,
				Flags:      ctmap.TUPLE_F_SERVICE,
			},
		},
	}
	v, err := ciliumCt6.Lookup(key.ToNetwork())
	if err != nil || v == nil {
		return nil
	}
	e := v.(*ctmap.CtEntry)
	backendId := e.RxBytes
	backendKey := lbmap.NewBackend6KeyV3(loadbalancer.BackendID(backendId))
	b, err := backends6Map.Lookup(backendKey)
	if err != nil || b == nil {
		return nil
	}
	var backend lbmap.BackendValue
	switch bv := b.(type) {
	case *lbmap.Backend6Value:
		backend = bv.ToHost()
	case *lbmap.Backend6ValueV3:
		backend = bv.ToHost()
	default:
		return nil
	}
	backendIP, _ := netaddr.FromStdIP(backend.GetAddress())
	res := netaddr.IPPortFrom(backendIP, backend.GetPort())
	return &res
}
