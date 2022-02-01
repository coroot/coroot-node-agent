package containers

import (
	"github.com/florianl/go-conntrack"
	"inet.af/netaddr"
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

func ConntrackGetActualDestination(src, dst netaddr.IPPort) (netaddr.IPPort, error) {
	if conntrackClient == nil {
		return dst, nil
	}

	tcp := uint8(syscall.IPPROTO_TCP)
	sip := src.IP().IPAddr().IP
	dip := dst.IP().IPAddr().IP
	sport := src.Port()
	dport := dst.Port()

	con := conntrack.Con{
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
	sessions, err := conntrackClient.Get(conntrack.Conntrack, family, con)
	if err != nil {
		return netaddr.IPPort{}, err
	}
	for _, s := range sessions {
		if s.Reply != nil && s.Reply.Src != nil && s.Reply.Proto != nil && s.Reply.Proto.SrcPort != nil {
			ip, _ := netaddr.FromStdIP(*s.Reply.Src)
			port := *s.Reply.Proto.SrcPort
			return netaddr.IPPortFrom(ip, port), nil
		}
	}
	return netaddr.IPPort{}, nil
}
