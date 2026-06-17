//go:build windows

package containers

import (
	"context"
	"testing"

	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestWindowsContainerID(t *testing.T) {
	cases := []struct {
		name        string
		runtime     string
		container   string
		labels      map[string]string
		env         map[string]string
		expected    ContainerID
		expectedApp string
	}{
		{
			name:      "plain docker",
			runtime:   "docker",
			container: "web",
			expected:  "/docker/web",
		},
		{
			name:    "kubernetes",
			runtime: "docker",
			labels: map[string]string{
				"io.kubernetes.pod.name":       "api-7d9d6b6b7d-q8s2x",
				"io.kubernetes.pod.namespace":  "default",
				"io.kubernetes.container.name": "api",
			},
			expected:    "/k8s/default/api-7d9d6b6b7d-q8s2x/api",
			expectedApp: "/k8s/default/api",
		},
		{
			name:    "pause container",
			runtime: "docker",
			labels: map[string]string{
				"io.kubernetes.pod.name":       "api-7d9d6b6b7d-q8s2x",
				"io.kubernetes.pod.namespace":  "default",
				"io.kubernetes.container.name": "POD",
			},
			expected: "",
		},
		{
			name:    "swarm",
			runtime: "docker",
			labels: map[string]string{
				"com.docker.stack.namespace":    "prod",
				"com.docker.swarm.service.name": "prod_web",
				"com.docker.swarm.task.name":    "prod_web.2.u6op4w8l1h",
			},
			expected: "/swarm/prod/web/2",
		},
		{
			name:    "nomad",
			runtime: "docker",
			env: map[string]string{
				"NOMAD_ALLOC_ID":   "alloc-1",
				"NOMAD_GROUP_NAME": "group",
				"NOMAD_JOB_NAME":   "job",
				"NOMAD_NAMESPACE":  "default",
				"NOMAD_TASK_NAME":  "task",
			},
			expected: "/nomad/default/job/group/alloc-1/task",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := windowsContainerID(tc.runtime, tc.container, tc.labels, tc.env)
			if id != tc.expected {
				t.Fatalf("windowsContainerID()=%q, want %q", id, tc.expected)
			}
			if appID := appIDForContainerID(id); appID != tc.expectedApp {
				t.Fatalf("appIDForContainerID(%q)=%q, want %q", id, appID, tc.expectedApp)
			}
		})
	}
}

func TestWindowsRegistryCollect(t *testing.T) {
	r := &Registry{
		sources: []windowsContainerSource{fakeWindowsContainerSource{
			containers: []windowsContainer{
				{ID: "/docker/web", Image: "mcr.microsoft.com/windows/nanoserver:ltsc2022", RestartCount: 2},
				{ID: "/k8s/default/api-7d9d6b6b7d-q8s2x/api", AppID: "/k8s/default/api", Image: "example/api:v1"},
			},
		}},
		network: newWindowsNetworkState(),
	}
	reg := prometheus.NewRegistry()
	if err := reg.Register(r); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}
	info := metricFamily(t, families, "container_info")
	if got := len(info.Metric); got != 2 {
		t.Fatalf("container_info samples=%d, want 2", got)
	}
	assertMetricLabels(t, info.Metric[0], map[string]string{
		"container_id":         "/docker/web",
		"app_id":               "",
		"image":                "mcr.microsoft.com/windows/nanoserver:ltsc2022",
		"systemd_triggered_by": "",
		"systemd_type":         "",
	})
	restarts := metricFamily(t, families, "container_restarts_total")
	if got := len(restarts.Metric); got != 2 {
		t.Fatalf("container_restarts_total samples=%d, want 2", got)
	}
}

func TestWindowsContainerProcessesFromTop(t *testing.T) {
	processes := windowsContainerProcessesFromTop(
		windowsContainer{ID: "/docker/web", AppID: "web"},
		dockercontainer.ContainerTopOKBody{
			Titles: []string{"Name", "PID", "SessionName"},
			Processes: [][]string{
				{"cmd.exe", "4242", "Console"},
				{"bad.exe", "not-a-pid", "Console"},
				{"short-row"},
				{"zero.exe", "0", "Console"},
			},
		},
	)
	if len(processes) != 1 {
		t.Fatalf("processes=%+v, want one valid process", processes)
	}
	if processes[0] != (windowsContainerProcess{Pid: 4242, ContainerID: "/docker/web", AppID: "web"}) {
		t.Fatalf("unexpected process: %+v", processes[0])
	}
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

type fakeWindowsContainerSource struct {
	containers []windowsContainer
}

func (s fakeWindowsContainerSource) Name() string { return "fake" }

func (s fakeWindowsContainerSource) Containers(ctx context.Context) ([]windowsContainer, error) {
	return s.containers, nil
}

func (s fakeWindowsContainerSource) Close() error { return nil }
