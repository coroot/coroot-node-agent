package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContainerIdToServiceName(t *testing.T) {
	f := ContainerIdToOtelServiceName
	assert.Equal(t,
		f("/k8s/otel-demo/otel-demo-frauddetectionservice-64cd4f9686-mvtnb/frauddetectionservice"),
		"/k8s/otel-demo/otel-demo-frauddetectionservice")

	assert.Equal(t,
		f("/k8s/coroot/coroot-node-agent-np9pk/node-agent"),
		"/k8s/coroot/coroot-node-agent")

	assert.Equal(t,
		f("/k8s/coroot/pyroscope-df884bb79-hhxtv/pyroscope"),
		"/k8s/coroot/pyroscope")

	assert.Equal(t,
		f("/k8s/default/cassandra-main-12/cassandra"),
		"/k8s/default/cassandra-main")

	assert.Equal(t,
		f("/k8s/default/hello-28283967-khz2f/xz"),
		"/k8s/default/hello")

	assert.Equal(t,
		f("/system.slice/k3s.service"),
		"/system.slice/k3s.service")

	assert.Equal(t,
		f("/docker/container_name"),
		"/docker/container_name")
}
