package node

import (
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	procRoot = "/proc"
)

type MemoryStat struct {
	TotalBytes     float64
	FreeBytes      float64
	AvailableBytes float64
	CachedBytes    float64
}

type CpuStat struct {
	TotalUsage   CpuUsage
	LogicalCores int
}

type CpuUsage struct {
	User    float64
	Nice    float64
	System  float64
	Idle    float64
	IoWait  float64
	Irq     float64
	SoftIrq float64
	Steal   float64
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ch <- metrics.Gauge(metrics.NodeInfo, 1, c.hostname, c.kernelVersion)

	v, err := uptime(procRoot)
	if err != nil {
		klog.Errorln(err)
	} else {
		ch <- metrics.Gauge(metrics.NodeUptime, v)
	}

	cpu, err := cpuStat(procRoot)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Errorln(err)
		}
	} else {
		ch <- metrics.Counter(metrics.NodeCPUUsage, cpu.TotalUsage.User, "user")
		ch <- metrics.Counter(metrics.NodeCPUUsage, cpu.TotalUsage.Nice, "nice")
		ch <- metrics.Counter(metrics.NodeCPUUsage, cpu.TotalUsage.System, "system")
		ch <- metrics.Counter(metrics.NodeCPUUsage, cpu.TotalUsage.Idle, "idle")
		ch <- metrics.Counter(metrics.NodeCPUUsage, cpu.TotalUsage.IoWait, "iowait")
		ch <- metrics.Counter(metrics.NodeCPUUsage, cpu.TotalUsage.Irq, "irq")
		ch <- metrics.Counter(metrics.NodeCPUUsage, cpu.TotalUsage.SoftIrq, "softirq")
		ch <- metrics.Counter(metrics.NodeCPUUsage, cpu.TotalUsage.Steal, "steal")
		ch <- metrics.Gauge(metrics.NodeCPULogicalCores, float64(cpu.LogicalCores))
	}

	mem, err := memoryInfo(procRoot)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Errorln(err)
		}
	} else {
		ch <- metrics.Gauge(metrics.NodeMemoryTotal, mem.TotalBytes)
		ch <- metrics.Gauge(metrics.NodeMemoryFree, mem.FreeBytes)
		ch <- metrics.Gauge(metrics.NodeMemoryAvailable, mem.AvailableBytes)
		ch <- metrics.Gauge(metrics.NodeMemoryCached, mem.CachedBytes)
	}

	disks, err := GetDisks()
	if err != nil {
		klog.Errorln("failed to get disk stats:", err)
	} else {
		for _, d := range disks.BlockDevices() {
			ch <- metrics.Counter(metrics.NodeDiskReads, d.ReadOps, d.Name)
			ch <- metrics.Counter(metrics.NodeDiskWrites, d.WriteOps, d.Name)
			ch <- metrics.Counter(metrics.NodeDiskReadBytes, d.BytesRead, d.Name)
			ch <- metrics.Counter(metrics.NodeDiskWrittenBytes, d.BytesWritten, d.Name)
			ch <- metrics.Counter(metrics.NodeDiskReadTime, d.ReadTimeSeconds, d.Name)
			ch <- metrics.Counter(metrics.NodeDiskWriteTime, d.WriteTimeSeconds, d.Name)
			ch <- metrics.Counter(metrics.NodeDiskIoTime, d.IoTimeSeconds, d.Name)
		}
	}

	netdev, err := NetDevices()
	if err != nil {
		klog.Errorln(err)
	} else {
		for _, dev := range netdev {
			ch <- metrics.Counter(metrics.NodeNetRxBytes, dev.RxBytes, dev.Name)
			ch <- metrics.Counter(metrics.NodeNetTxBytes, dev.TxBytes, dev.Name)
			ch <- metrics.Counter(metrics.NodeNetRxPackets, dev.RxPackets, dev.Name)
			ch <- metrics.Counter(metrics.NodeNetTxPackets, dev.TxPackets, dev.Name)
			ch <- metrics.Gauge(metrics.NodeNetInterfaceUp, dev.Up, dev.Name)
			for _, p := range dev.IPPrefixes {
				ch <- metrics.Gauge(metrics.NodeNetInterfaceIP, 1, dev.Name, p.IP().String())
			}
		}
	}
	ch <- metrics.Gauge(metrics.NodeCloudInfo, 1,
		string(c.instanceMetadata.Provider), c.instanceMetadata.AccountId, c.instanceMetadata.InstanceId,
		c.instanceMetadata.InstanceType, c.instanceMetadata.LifeCycle,
		c.instanceMetadata.Region, c.instanceMetadata.AvailabilityZone, c.instanceMetadata.AvailabilityZoneId,
		c.instanceMetadata.LocalIPv4, c.instanceMetadata.PublicIPv4,
	)
}
