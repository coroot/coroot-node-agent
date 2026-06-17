//go:build windows

package containers

import (
	"sync"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/etwtracer"
	"github.com/prometheus/client_golang/prometheus"
	"inet.af/netaddr"
)

var (
	windowsNetConnectionsSuccessfulDesc = prometheus.NewDesc(
		"container_net_tcp_successful_connects_total",
		"Total number of successful TCP connects",
		[]string{"container_id", "app_id", "destination", "actual_destination"}, nil,
	)
	windowsNetConnectionsActiveDesc = prometheus.NewDesc(
		"container_net_tcp_active_connections",
		"Number of active outbound connections used by the container",
		[]string{"container_id", "app_id", "destination", "actual_destination"}, nil,
	)
	windowsNetBytesSentDesc = prometheus.NewDesc(
		"container_net_tcp_bytes_sent_total",
		"Total number of bytes sent to the peer",
		[]string{"container_id", "app_id", "destination", "actual_destination"}, nil,
	)
	windowsNetBytesReceivedDesc = prometheus.NewDesc(
		"container_net_tcp_bytes_received_total",
		"Total number of bytes received from the peer",
		[]string{"container_id", "app_id", "destination", "actual_destination"}, nil,
	)
)

type windowsContainerProcess struct {
	Pid         uint32
	ContainerID ContainerID
	AppID       string
}

type windowsNetworkState struct {
	lock sync.RWMutex

	processes map[uint32]windowsContainerProcess
	tcp       map[windowsContainerIdentity]map[windowsDestinationKey]*windowsTCPStats
	active    map[windowsConnectionKey]*windowsTCPStats
	seen      map[windowsConnectionKey]struct{}
}

type windowsContainerIdentity struct {
	id    ContainerID
	appID string
}

type windowsDestinationKey struct {
	destination       string
	actualDestination string
}

type windowsConnectionKey struct {
	container windowsContainerIdentity
	pid       uint32
	connID    string
	src       string
	dst       string
}

type windowsTCPStats struct {
	successful    uint64
	bytesSent     uint64
	bytesReceived uint64
	active        map[windowsConnectionKey]struct{}
}

func newWindowsNetworkState() *windowsNetworkState {
	return &windowsNetworkState{
		processes: map[uint32]windowsContainerProcess{},
		tcp:       map[windowsContainerIdentity]map[windowsDestinationKey]*windowsTCPStats{},
		active:    map[windowsConnectionKey]*windowsTCPStats{},
		seen:      map[windowsConnectionKey]struct{}{},
	}
}

func (s *windowsNetworkState) Describe(ch chan<- *prometheus.Desc) {
	ch <- windowsNetConnectionsSuccessfulDesc
	ch <- windowsNetConnectionsActiveDesc
	ch <- windowsNetBytesSentDesc
	ch <- windowsNetBytesReceivedDesc
}

func (s *windowsNetworkState) ReplaceProcesses(processes []windowsContainerProcess) {
	next := make(map[uint32]windowsContainerProcess, len(processes))
	for _, p := range processes {
		next[p.Pid] = p
	}
	s.lock.Lock()
	s.processes = next
	s.lock.Unlock()
}

func (s *windowsNetworkState) Observe(event etwtracer.Event) {
	peer := windowsEventPeer(event)
	local := windowsEventLocal(event)
	if event.Pid == 0 || !peer.IP().IsValid() {
		return
	}
	if common.PortFilter != nil && common.PortFilter.ShouldBeSkipped(peer.Port()) {
		return
	}
	if common.ConnectionFilter.ShouldBeSkipped(peer.IP(), peer.IP()) {
		return
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	process, ok := s.processes[event.Pid]
	if !ok {
		return
	}
	container := windowsContainerIdentity{id: process.ContainerID, appID: process.AppID}
	destination := windowsDestinationKey{
		destination:       peer.String(),
		actualDestination: peer.String(),
	}
	stats := s.stats(container, destination)
	connection := windowsConnectionKey{
		container: container,
		pid:       event.Pid,
		connID:    event.ConnID,
		src:       local.String(),
		dst:       peer.String(),
	}

	switch event.Type {
	case etwtracer.EventTypeTCPDataSent:
		s.markSuccessful(connection, stats)
		stats.bytesSent += event.Bytes
		s.markActive(connection, stats)
	case etwtracer.EventTypeTCPDataReceived:
		s.markSuccessful(connection, stats)
		stats.bytesReceived += event.Bytes
		s.markActive(connection, stats)
	case etwtracer.EventTypeTCPConnectionAttempted, etwtracer.EventTypeTCPReconnectAttempted:
		s.markActive(connection, stats)
	case etwtracer.EventTypeTCPDisconnect:
		s.markInactive(connection)
	}
}

func windowsEventPeer(event etwtracer.Event) netaddr.IPPort {
	if event.Type == etwtracer.EventTypeTCPDataReceived {
		return event.Src
	}
	return event.Dst
}

func windowsEventLocal(event etwtracer.Event) netaddr.IPPort {
	if event.Type == etwtracer.EventTypeTCPDataReceived {
		return event.Dst
	}
	return event.Src
}

func (s *windowsNetworkState) Collect(ch chan<- prometheus.Metric) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	for container, byDestination := range s.tcp {
		for destination, stats := range byDestination {
			labels := []string{string(container.id), container.appID, destination.destination, destination.actualDestination}
			if stats.successful > 0 {
				ch <- prometheus.MustNewConstMetric(windowsNetConnectionsSuccessfulDesc, prometheus.CounterValue, float64(stats.successful), labels...)
			}
			if stats.bytesSent > 0 {
				ch <- prometheus.MustNewConstMetric(windowsNetBytesSentDesc, prometheus.CounterValue, float64(stats.bytesSent), labels...)
			}
			if stats.bytesReceived > 0 {
				ch <- prometheus.MustNewConstMetric(windowsNetBytesReceivedDesc, prometheus.CounterValue, float64(stats.bytesReceived), labels...)
			}
			if active := len(stats.active); active > 0 {
				ch <- prometheus.MustNewConstMetric(windowsNetConnectionsActiveDesc, prometheus.GaugeValue, float64(active), labels...)
			}
		}
	}
}

func (s *windowsNetworkState) stats(container windowsContainerIdentity, destination windowsDestinationKey) *windowsTCPStats {
	byDestination := s.tcp[container]
	if byDestination == nil {
		byDestination = map[windowsDestinationKey]*windowsTCPStats{}
		s.tcp[container] = byDestination
	}
	stats := byDestination[destination]
	if stats == nil {
		stats = &windowsTCPStats{active: map[windowsConnectionKey]struct{}{}}
		byDestination[destination] = stats
	}
	return stats
}

func (s *windowsNetworkState) markSuccessful(connection windowsConnectionKey, stats *windowsTCPStats) {
	if _, ok := s.seen[connection]; ok {
		return
	}
	s.seen[connection] = struct{}{}
	stats.successful++
}

func (s *windowsNetworkState) markActive(connection windowsConnectionKey, stats *windowsTCPStats) {
	stats.active[connection] = struct{}{}
	s.active[connection] = stats
}

func (s *windowsNetworkState) markInactive(connection windowsConnectionKey) {
	stats := s.active[connection]
	if stats == nil {
		return
	}
	delete(stats.active, connection)
	delete(s.active, connection)
}
