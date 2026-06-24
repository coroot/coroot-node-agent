package node

import (
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/coroot/coroot-node-agent/node/metadata"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

type Collector struct {
	hostname         string
	kernelVersion    string
	instanceMetadata *metadata.CloudMetadata
}

func NewCollector(hostname, kernelVersion string, overrides metadata.Overrides) *Collector {
	md := metadata.GetInstanceMetadata()
	if md == nil {
		md = &metadata.CloudMetadata{}
	}
	md.ApplyOverrides(overrides)
	klog.Infof("instance metadata: %+v", md)
	return &Collector{
		hostname:         hostname,
		kernelVersion:    kernelVersion,
		instanceMetadata: md,
	}
}

func (c *Collector) Metadata() *metadata.CloudMetadata {
	return c.instanceMetadata
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.NodeInfo
	ch <- metrics.NodeCloudInfo
	ch <- metrics.NodeUptime
	ch <- metrics.NodeCPUUsage
	ch <- metrics.NodeCPULogicalCores
	ch <- metrics.NodeMemoryTotal
	ch <- metrics.NodeMemoryFree
	ch <- metrics.NodeMemoryAvailable
	ch <- metrics.NodeMemoryCached
	ch <- metrics.NodeDiskReads
	ch <- metrics.NodeDiskWrites
	ch <- metrics.NodeDiskReadBytes
	ch <- metrics.NodeDiskWrittenBytes
	ch <- metrics.NodeDiskReadTime
	ch <- metrics.NodeDiskWriteTime
	ch <- metrics.NodeDiskIoTime
	ch <- metrics.NodeNetRxBytes
	ch <- metrics.NodeNetTxBytes
	ch <- metrics.NodeNetRxPackets
	ch <- metrics.NodeNetTxPackets
	ch <- metrics.NodeNetInterfaceUp
	ch <- metrics.NodeNetInterfaceIP
}
