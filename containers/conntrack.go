package containers

import (
	"github.com/coroot/coroot-node-agent/common"
	"github.com/florianl/go-conntrack"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
	"syscall"
)

var (
	conntrackClient *conntrack.Nfct
)

func ConntrackInit() error {
	c, err := conntrack.Open(&conntrack.Config{})
	if err != nil {
		return err
	}
	conntrackClient = c
	return nil
}

func ConntrackGetActualDestination(src, dst netaddr.IPPort) netaddr.IPPort {
	if conntrackClient == nil {
		return dst
	}

	tcp := uint8(syscall.IPPROTO_TCP)
	sip := src.IP().IPAddr().IP
	dip := dst.IP().IPAddr().IP
	sport := src.Port()
	dport := dst.Port()

	req := conntrack.Con{
		Origin: &conntrack.IPTuple{
			Src: &sip,
			Dst: &dip,
			Proto: &conntrack.ProtoTuple{
				Number:  &tcp,
				SrcPort: &sport,
				DstPort: &dport,
			},
		},
	}
	family := conntrack.IPv4
	if dst.IP().Is6() {
		family = conntrack.IPv6
	}
	sessions, err := conntrackClient.Get(conntrack.Conntrack, family, req)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Errorf("failed to resolve actual destination for %s->%s: %s", src, dst, err)
		}
		return dst
	}
	for _, s := range sessions {
		if !ipTupleValid(s.Origin) || !ipTupleValid(s.Reply) {
			continue
		}
		var reply *conntrack.IPTuple
		if ipTuplesEqual(req.Origin, s.Origin) {
			reply = s.Reply
		} else if ipTuplesEqual(req.Origin, s.Reply) {
			reply = s.Origin
		}
		if reply == nil {
			continue
		}
		ip, ok := netaddr.FromStdIP(*reply.Src)
		if !ok {
			continue
		}
		return netaddr.IPPortFrom(ip, *reply.Proto.SrcPort)
	}
	return dst
}

func ipTuplesEqual(a, b *conntrack.IPTuple) bool {
	return a.Src.Equal(*b.Src) && a.Dst.Equal(*b.Dst) && *a.Proto.SrcPort == *b.Proto.SrcPort && *a.Proto.DstPort == *b.Proto.DstPort
}

func ipTupleValid(t *conntrack.IPTuple) bool {
	if t == nil {
		return false
	}
	if t.Src == nil || t.Dst == nil || t.Proto == nil {
		return false
	}
	if t.Proto.SrcPort == nil || t.Proto.DstPort == nil {
		return false
	}
	return true
}
