//go:build windows

package containers

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/coroot/logparser"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestWindowsContainerLogStateParsesDockerJSONLogs(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "docker-json-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	state := newWindowsContainerLogState()
	defer state.Close()
	state.Sync([]windowsContainer{{
		ID:         "/docker/web",
		AppID:      "",
		LogPath:    f.Name(),
		LogDecoder: logparser.DockerJsonDecoder{},
	}})

	for i := 0; i < 2; i++ {
		_, err = fmt.Fprintf(f, `{"log":"ERROR coroot m4 log line %d\n","stream":"stdout","time":"2026-06-17T00:00:00Z"}`+"\n", i)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}

	families := waitForLogMetric(t, state, 5*time.Second)
	logs := metricFamily(t, families, "container_log_messages_total")
	if len(logs.Metric) == 0 {
		t.Fatal("container_log_messages_total has no samples")
	}
	assertMetricLabels(t, logs.Metric[0], map[string]string{
		"container_id": "/docker/web",
		"app_id":       "",
		"source":       windowsContainerLogSource,
		"level":        "error",
	})
}

func waitForLogMetric(t *testing.T, state *windowsContainerLogState, timeout time.Duration) []*dto.MetricFamily {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		reg := prometheus.NewRegistry()
		if err := reg.Register(state); err != nil {
			t.Fatalf("register failed: %v", err)
		}
		families, err := reg.Gather()
		if err != nil {
			t.Fatalf("gather failed: %v", err)
		}
		if family := findMetricFamily(families, "container_log_messages_total"); family != nil && len(family.Metric) > 0 {
			return families
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("container_log_messages_total did not appear within %s", timeout)
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
