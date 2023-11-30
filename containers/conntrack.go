package containers

import (
	"syscall"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/florianl/go-conntrack"
	"github.com/vishvananda/netns"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

type Conntrack struct {
	client *conntrack.Nfct
}

func NewConntrack(netNs netns.NsHandle) (*Conntrack, error) {
	c, err := conntrack.Open(&conntrack.Config{NetNS: int(netNs)})
	if err != nil {
		return nil, err
	}
	return &Conntrack{client: c}, nil
}

func (c *Conntrack) GetActualDestination(src, dst netaddr.IPPort) *netaddr.IPPort {
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
	sessions, err := c.client.Get(conntrack.Conntrack, family, req)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Errorf("failed to resolve actual destination for %s->%s: %s", src, dst, err)
		}
		return nil
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
		res := netaddr.IPPortFrom(ip, *reply.Proto.SrcPort)
		return &res
	}
	return nil
}

func (c *Conntrack) Close() error {
	return c.client.Close()
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
