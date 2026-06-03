//go:build windows

package nettracer

import (
	"sync"

	"github.com/coroot/coroot-node-agent/common"
	"inet.af/netaddr"
)

const maxDNSEntries = 100000

type DNSCache struct {
	lock    sync.RWMutex
	domains map[netaddr.IP]*common.Domain
}

func NewDNSCache() *DNSCache {
	return &DNSCache{domains: map[netaddr.IP]*common.Domain{}}
}

func (dc *DNSCache) update(fqdn string, ips []netaddr.IP) {
	if fqdn == "" || len(ips) == 0 {
		return
	}
	d := common.NewDomain(fqdn, ips)
	dc.lock.Lock()
	if len(dc.domains) >= maxDNSEntries {
		dc.domains = make(map[netaddr.IP]*common.Domain, len(ips))
	}
	for _, ip := range ips {
		dc.domains[ip] = d
	}
	dc.lock.Unlock()
}

func (dc *DNSCache) domain(ip netaddr.IP) *common.Domain {
	dc.lock.RLock()
	defer dc.lock.RUnlock()
	return dc.domains[ip]
}
