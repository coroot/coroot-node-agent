//go:build windows

package containers

import (
	"testing"

	"github.com/coroot/coroot-node-agent/etwtracer"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"inet.af/netaddr"
)

func TestWindowsNetworkStateCollectsTCPMetrics(t *testing.T) {
	state := newWindowsNetworkState()
	state.ReplaceProcesses([]windowsContainerProcess{{Pid: 4242, ContainerID: "/docker/web", AppID: ""}})
	src := netaddr.MustParseIPPort("10.0.0.2:50000")
	dst := netaddr.MustParseIPPort("10.0.0.3:80")

	state.Observe(etwtracer.Event{Type: etwtracer.EventTypeTCPConnectionAttempted, Pid: 4242, Src: src, Dst: dst, ConnID: "7"})
	state.Observe(etwtracer.Event{Type: etwtracer.EventTypeTCPDataSent, Pid: 4242, Src: src, Dst: dst, Bytes: 100, ConnID: "7"})
	state.Observe(etwtracer.Event{Type: etwtracer.EventTypeTCPDataReceived, Pid: 4242, Src: dst, Dst: src, Bytes: 40, ConnID: "7"})

	reg := prometheus.NewRegistry()
	reg.MustRegister(state)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	assertWindowsNetworkMetric(t, families, "container_net_tcp_active_connections", prometheus.GaugeValue, 1)
	assertWindowsNetworkMetric(t, families, "container_net_tcp_bytes_received_total", prometheus.CounterValue, 40)
	assertWindowsNetworkMetric(t, families, "container_net_tcp_bytes_sent_total", prometheus.CounterValue, 100)
	assertWindowsNetworkMetric(t, families, "container_net_tcp_successful_connects_total", prometheus.CounterValue, 1)
}

func assertWindowsNetworkMetric(t *testing.T, families []*dto.MetricFamily, name string, valueType prometheus.ValueType, want float64) {
	t.Helper()
	family := findWindowsNetworkMetricFamily(t, families, name)
	if got := len(family.Metric); got != 1 {
		t.Fatalf("%s samples=%d, want 1", name, got)
	}
	metric := family.Metric[0]
	labels := map[string]string{}
	for _, label := range metric.Label {
		labels[label.GetName()] = label.GetValue()
	}
	expectedLabels := map[string]string{
		"actual_destination": "10.0.0.3:80",
		"app_id":             "",
		"container_id":       "/docker/web",
		"destination":        "10.0.0.3:80",
	}
	for label, expected := range expectedLabels {
		if got := labels[label]; got != expected {
			t.Fatalf("%s label %s=%q, want %q; labels=%v", name, label, got, expected, labels)
		}
	}
	switch valueType {
	case prometheus.CounterValue:
		if got := metric.GetCounter().GetValue(); got != want {
			t.Fatalf("%s counter=%v, want %v", name, got, want)
		}
	case prometheus.GaugeValue:
		if got := metric.GetGauge().GetValue(); got != want {
			t.Fatalf("%s gauge=%v, want %v", name, got, want)
		}
	default:
		t.Fatalf("unsupported metric type %v", valueType)
	}
}

func findWindowsNetworkMetricFamily(t *testing.T, families []*dto.MetricFamily, name string) *dto.MetricFamily {
	t.Helper()
	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}
	t.Fatalf("metric family %q not found", name)
	return nil
}
