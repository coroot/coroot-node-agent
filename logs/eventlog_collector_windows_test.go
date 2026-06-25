//go:build windows

package logs

import (
	"sync"
	"testing"
	"time"

	"github.com/coroot/logparser"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestEventLogCollectorCollectsMetricLabels(t *testing.T) {
	poller := &fakeEventLogPoller{entries: []LogEntry{{
		Timestamp: time.Now(),
		Channel:   "Application",
		Provider:  "CorootTest",
		EventID:   4242,
		Level:     logparser.LevelError,
		Message:   "ERROR coroot event log test line 1",
	}}}
	collector := newEventLogCollector(poller, 10*time.Millisecond)
	defer collector.Close()

	families := waitForEventLogMetric(t, collector, 5*time.Second)
	metric := metricFamily(t, families, "windows_event_log_messages_total")
	if len(metric.Metric) == 0 {
		t.Fatal("windows_event_log_messages_total has no samples")
	}
	assertMetricLabels(t, metric.Metric[0], map[string]string{
		"channel":  "Application",
		"provider": "CorootTest",
		"event_id": "4242",
		"level":    "error",
	})
}

func TestNormalizeEventLogChannels(t *testing.T) {
	got := normalizeEventLogChannels([]string{"Application", " ", "System", "Application"})
	want := []string{"Application", "System"}
	if len(got) != len(want) {
		t.Fatalf("channels=%v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("channels=%v, want %v", got, want)
		}
	}
	got = normalizeEventLogChannels(nil)
	if len(got) != 2 || got[0] != "Application" || got[1] != "System" {
		t.Fatalf("default channels=%v, want [Application System]", got)
	}
}

func waitForEventLogMetric(t *testing.T, collector *EventLogCollector, timeout time.Duration) []*dto.MetricFamily {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		reg := prometheus.NewRegistry()
		if err := reg.Register(collector); err != nil {
			t.Fatalf("register failed: %v", err)
		}
		families, err := reg.Gather()
		if err != nil {
			t.Fatalf("gather failed: %v", err)
		}
		if family := findMetricFamily(families, "windows_event_log_messages_total"); family != nil && len(family.Metric) > 0 {
			return families
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("windows_event_log_messages_total did not appear within %s", timeout)
	return nil
}

func findMetricFamily(families []*dto.MetricFamily, name string) *dto.MetricFamily {
	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}
	return nil
}

func metricFamily(t *testing.T, families []*dto.MetricFamily, name string) *dto.MetricFamily {
	t.Helper()
	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}
	t.Fatalf("metric family %q not found", name)
	return nil
}

func assertMetricLabels(t *testing.T, metric *dto.Metric, expected map[string]string) {
	t.Helper()
	got := map[string]string{}
	for _, label := range metric.Label {
		got[label.GetName()] = label.GetValue()
	}
	for k, v := range expected {
		if got[k] != v {
			t.Fatalf("label %s=%q, want %q; all labels=%v", k, got[k], v, got)
		}
	}
}

type fakeEventLogPoller struct {
	lock    sync.Mutex
	entries []LogEntry
	closed  bool
}

func (p *fakeEventLogPoller) Poll() []LogEntry {
	p.lock.Lock()
	defer p.lock.Unlock()
	entries := p.entries
	p.entries = nil
	return entries
}

func (p *fakeEventLogPoller) Close() {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.closed = true
}
