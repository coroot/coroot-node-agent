package l7

import (
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
)

func ParseDns(payload []byte) (string, string, []netaddr.IP) {
	var msg dnsmessage.Message
	if err := msg.Unpack(payload); err != nil {
		return "", "", nil
	}
	if len(msg.Questions) < 1 {
		return "", "", nil
	}
	var ips []netaddr.IP
	for _, a := range msg.Answers {
		switch a.Header.Type {
		case dnsmessage.TypeA:
			if r, ok := a.Body.(*dnsmessage.AResource); ok {
				ips = append(ips, netaddr.IPFrom4(r.A))
			}
		case dnsmessage.TypeAAAA:
			if r, ok := a.Body.(*dnsmessage.AAAAResource); ok {
				ips = append(ips, netaddr.IPFrom16(r.AAAA))
			}
		}
	}
	q := msg.Questions[0]
	return q.Type.String(), strings.TrimSuffix(q.Name.String(), "."), ips
}
