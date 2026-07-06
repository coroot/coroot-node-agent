//go:build linux

package node

import (
	"strings"
	"testing"

	"github.com/coroot/coroot-node-agent/node/metadata"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestNodeInfoIncludesAgentVersion verifies that the node_info metric carries
// the agent_version label, as documented at
// https://docs.coroot.com/metrics/node-agent/#node_info (see issue #215).
func TestNodeInfoIncludesAgentVersion(t *testing.T) {
	c := &Collector{
		hostname:         "test-host",
		kernelVersion:    "6.1.0-test",
		agentVersion:     "v1.2.3-test",
		instanceMetadata: &metadata.CloudMetadata{},
	}

	ch := make(chan prometheus.Metric, 1024)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	var nodeInfo *dto.Metric
	for m := range ch {
		if !strings.Contains(m.Desc().String(), `fqName: "node_info"`) {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("failed to write node_info metric: %v", err)
		}
		nodeInfo = &pb
	}

	if nodeInfo == nil {
		t.Fatal("node_info metric was not emitted")
	}

	labels := map[string]string{}
	for _, lp := range nodeInfo.Label {
		labels[lp.GetName()] = lp.GetValue()
	}

	if got := labels["agent_version"]; got != "v1.2.3-test" {
		t.Fatalf("node_info agent_version label = %q, want %q (all labels: %v)", got, "v1.2.3-test", labels)
	}
}
