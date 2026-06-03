//go:build windows

package nettracer

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/coroot/coroot-node-agent/common"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

type ListenAddr struct {
	Addr string
	Port uint16
	PID  uint32
}

type Destination struct {
	Destination       string
	ActualDestination string
	ActiveCount       int64
	SuccessfulCount   int64
	FailedCount       int64
}

type ServiceNetStats struct {
	ListenAddrs  []ListenAddr
	Destinations []*Destination
	ActiveConns  int64
}

type Tracker struct {
	lock    sync.Mutex
	success map[uint32]map[string]int64 // pid -> dest -> count
	failed  map[uint32]map[string]int64 // pid -> dest -> count
	etw     *ETWTracer
	dns     *DNSCache

	connList atomic.Pointer[[]tcpConn]
}

func (t *Tracker) RefreshConnections() {
	conns := listTCPConnections()
	t.connList.Store(&conns)
}

func NewTracker(onDNSRequest func(*DNSRequest)) *Tracker {
	t := &Tracker{
		success: make(map[uint32]map[string]int64),
		failed:  make(map[uint32]map[string]int64),
		dns:     NewDNSCache(),
	}

	etw, err := NewETWTracer(t.handleNetworkEvent, t.dns.update, onDNSRequest)
	if err != nil {
		klog.Warningf("ETW tracer failed: %v", err)
	} else {
		t.etw = etw
	}

	return t
}

func (t *Tracker) handleNetworkEvent(event *NetworkEvent) {
	dest := event.RemoteAddrPort

	t.lock.Lock()
	counts := t.success
	if !event.Succeeded {
		counts = t.failed
	}
	if counts[event.PID] == nil {
		counts[event.PID] = make(map[string]int64)
	}
	counts[event.PID][dest]++
	t.lock.Unlock()
}

func (t *Tracker) RetainPIDs(livePIDs map[uint32]int) {
	t.lock.Lock()
	defer t.lock.Unlock()
	for _, m := range []map[uint32]map[string]int64{t.success, t.failed} {
		for pid := range m {
			if _, ok := livePIDs[pid]; !ok {
				delete(m, pid)
			}
		}
	}
}

func (t *Tracker) GetServiceStats(pids []uint32) *ServiceNetStats {
	var connections []tcpConn
	if p := t.connList.Load(); p != nil {
		connections = *p
	}

	pidSet := make(map[uint32]bool)
	for _, pid := range pids {
		pidSet[pid] = true
	}

	stats := &ServiceNetStats{}

	type counts struct{ active, successful, failed int64 }
	raw := map[string]*counts{}
	get := func(dest string) *counts {
		c := raw[dest]
		if c == nil {
			c = &counts{}
			raw[dest] = c
		}
		return c
	}

	listenPorts := map[uint16]bool{}
	var established []tcpConn
	for _, c := range connections {
		if !pidSet[c.PID] {
			continue
		}
		switch c.State {
		case tcpStateListen:
			listenPorts[c.LocalPort] = true
			stats.ListenAddrs = append(stats.ListenAddrs, ListenAddr{
				Addr: c.LocalIP,
				Port: c.LocalPort,
				PID:  c.PID,
			})
		case tcpStateEstablished:
			established = append(established, c)
		}
	}
	for _, c := range established {
		if listenPorts[c.LocalPort] {
			continue // inbound: a client connected to a port we listen on
		}
		get(net.JoinHostPort(c.RemoteIP, strconv.Itoa(int(c.RemotePort)))).active++
		stats.ActiveConns++
	}

	t.lock.Lock()
	for _, pid := range pids {
		for dest, count := range t.success[pid] {
			get(dest).successful += count
		}
		for dest, count := range t.failed[pid] {
			get(dest).failed += count
		}
	}
	t.lock.Unlock()

	agg := map[[2]string]*Destination{}
	for dest, c := range raw {
		destination, actualDest := t.resolveDest(dest)
		key := [2]string{destination, actualDest}
		d := agg[key]
		if d == nil {
			d = &Destination{Destination: destination, ActualDestination: actualDest}
			agg[key] = d
		}
		d.ActiveCount += c.active
		d.SuccessfulCount += c.successful
		d.FailedCount += c.failed
	}
	for _, d := range agg {
		stats.Destinations = append(stats.Destinations, d)
	}

	return stats
}

func (t *Tracker) resolveDest(dest string) (destination, actualDestination string) {
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return dest, dest
	}
	ip, err := netaddr.ParseIP(host)
	if err != nil {
		return dest, dest
	}
	d := t.dns.domain(ip)
	if d == nil {
		return dest, dest
	}
	fqdnDest := net.JoinHostPort(d.FQDN, port)
	if !d.SpecifyIP && common.IsIpExternal(ip) {
		return fqdnDest, ""
	}
	return dest, dest
}

func (t *Tracker) Stop() {
	if t.etw != nil {
		t.etw.Stop()
	}
}
