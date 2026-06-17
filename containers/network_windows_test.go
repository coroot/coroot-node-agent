//go:build windows

package containers

import (
	"strings"
	"testing"

	"github.com/coroot/coroot-node-agent/etwtracer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"inet.af/netaddr"
)

func TestWindowsNetworkStateCollectsTCPMetrics(t *testing.T) {
	state := newWindowsNetworkState()
	state.ReplaceProcesses([]windowsContainerProcess{{Pid: 4242, ContainerID: "/docker/web", AppID: ""}})
	src := netaddr.MustParseIPPort("10.0.0.2:50000")
	dst := netaddr.MustParseIPPort("93.184.216.34:80")

	state.Observe(etwtracer.Event{Type: etwtracer.EventTypeTCPConnectionAttempted, Pid: 4242, Src: src, Dst: dst, ConnID: "7"})
	state.Observe(etwtracer.Event{Type: etwtracer.EventTypeTCPDataSent, Pid: 4242, Src: src, Dst: dst, Bytes: 100, ConnID: "7"})
	state.Observe(etwtracer.Event{Type: etwtracer.EventTypeTCPDataReceived, Pid: 4242, Src: dst, Dst: src, Bytes: 40, ConnID: "7"})

	reg := prometheus.NewRegistry()
	reg.MustRegister(state)
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP container_net_tcp_active_connections Number of active outbound connections used by the container
# TYPE container_net_tcp_active_connections gauge
container_net_tcp_active_connections{actual_destination="93.184.216.34:80",app_id="",container_id="/docker/web",destination="93.184.216.34:80"} 1
# HELP container_net_tcp_bytes_received_total Total number of bytes received from the peer
# TYPE container_net_tcp_bytes_received_total counter
container_net_tcp_bytes_received_total{actual_destination="93.184.216.34:80",app_id="",container_id="/docker/web",destination="93.184.216.34:80"} 40
# HELP container_net_tcp_bytes_sent_total Total number of bytes sent to the peer
# TYPE container_net_tcp_bytes_sent_total counter
container_net_tcp_bytes_sent_total{actual_destination="93.184.216.34:80",app_id="",container_id="/docker/web",destination="93.184.216.34:80"} 100
# HELP container_net_tcp_successful_connects_total Total number of successful TCP connects
# TYPE container_net_tcp_successful_connects_total counter
container_net_tcp_successful_connects_total{actual_destination="93.184.216.34:80",app_id="",container_id="/docker/web",destination="93.184.216.34:80"} 1
`), "container_net_tcp_successful_connects_total", "container_net_tcp_active_connections", "container_net_tcp_bytes_sent_total", "container_net_tcp_bytes_received_total"); err != nil {
		t.Fatalf("unexpected metrics mismatch: %s", err)
	}
}
