package node

import (
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/node/metadata"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	procRoot = "/proc"

	infoDesc = prometheus.NewDesc(
		"node_info",
		"Meta information about the node",
		[]string{"hostname", "kernel_version"}, nil,
	)
	cloudInfoDesc = prometheus.NewDesc(
		"node_cloud_info",
		"Meta information about the cloud instance",
		[]string{"provider", "account_id", "instance_id", "instance_type", "instance_life_cycle", "region", "availability_zone", "availability_zone_id", "local_ipv4", "public_ipv4"}, nil,
	)
	uptimeDesc = prometheus.NewDesc(
		"node_uptime_seconds",
		"Uptime of the node in seconds",
		[]string{}, nil,
	)
	cpuUsageDesc = prometheus.NewDesc(
		"node_resources_cpu_usage_seconds_total",
		"The amount of CPU time spent in each mode",
		[]string{"mode"}, nil,
	)
	cpuLogicalCoresDesc = prometheus.NewDesc(
		"node_resources_cpu_logical_cores",
		"The number of logical CPU cores",
		nil, nil,
	)
	memTotalDesc = prometheus.NewDesc(
		"node_resources_memory_total_bytes",
		"The total amount of physical memory",
		nil, nil,
	)
	memFreeDesc = prometheus.NewDesc(
		"node_resources_memory_free_bytes",
		"The amount of unassigned memory",
		nil, nil,
	)
	memAvailableDesc = prometheus.NewDesc(
		"node_resources_memory_available_bytes",
		"The total amount of available memory",
		nil, nil,
	)
	memCacheDesc = prometheus.NewDesc(
		"node_resources_memory_cached_bytes",
		"The amount of memory used as page cache",
		nil, nil,
	)
	diskReadsDesc = prometheus.NewDesc(
		"node_resources_disk_reads_total",
		"The total number of reads completed successfully",
		[]string{"device"}, nil,
	)
	diskWritesDesc = prometheus.NewDesc(
		"node_resources_disk_writes_total",
		"The total number of writes completed successfully",
		[]string{"device"}, nil,
	)
	diskReadBytesDesc = prometheus.NewDesc(
		"node_resources_disk_read_bytes_total",
		"The total number of bytes read from the disk",
		[]string{"device"}, nil,
	)
	diskWrittenBytesDesc = prometheus.NewDesc(
		"node_resources_disk_written_bytes_total",
		"The total number of bytes written to the disk",
		[]string{"device"}, nil,
	)
	diskReadTimeDesc = prometheus.NewDesc(
		"node_resources_disk_read_time_seconds_total",
		"The total number of seconds spent reading",
		[]string{"device"}, nil,
	)
	diskWriteTimeDesc = prometheus.NewDesc(
		"node_resources_disk_write_time_seconds_total",
		"The total number of seconds spent writing",
		[]string{"device"}, nil,
	)
	diskIoTimeDesc = prometheus.NewDesc(
		"node_resources_disk_io_time_seconds_total",
		"The total number of seconds the disk spent doing I/O",
		[]string{"device"}, nil,
	)
	netRxBytesDesc = prometheus.NewDesc(
		"node_net_received_bytes_total",
		"The total number of bytes received",
		[]string{"interface"}, nil,
	)
	netTxBytesDesc = prometheus.NewDesc(
		"node_net_transmitted_bytes_total",
		"The total number of bytes transmitted",
		[]string{"interface"}, nil,
	)
	netRxPacketsDesc = prometheus.NewDesc(
		"node_net_received_packets_total",
		"The total number of packets received",
		[]string{"interface"}, nil,
	)
	netTxPacketsDesc = prometheus.NewDesc(
		"node_net_transmitted_packets_total",
		"The total number of packets transmitted",
		[]string{"interface"}, nil,
	)
	netIfaceUpDesc = prometheus.NewDesc(
		"node_net_interface_up",
		"Status of the interface (0:down, 1:up)",
		[]string{"interface"}, nil,
	)
	ipDesc = prometheus.NewDesc(
		"node_net_interface_ip",
		"IP address assigned to the interface",
		[]string{"interface", "ip"}, nil,
	)
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

type Collector struct {
	hostname         string
	kernelVersion    string
	instanceMetadata *metadata.CloudMetadata
}

func NewCollector(hostname, kernelVersion string) *Collector {
	md := metadata.GetInstanceMetadata()
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

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ch <- gauge(infoDesc, 1, c.hostname, c.kernelVersion)

	v, err := uptime(procRoot)
	if err != nil {
		klog.Errorln(err)
	} else {
		ch <- gauge(uptimeDesc, v)
	}

	cpu, err := cpuStat(procRoot)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Errorln(err)
		}
	} else {
		ch <- counter(cpuUsageDesc, cpu.TotalUsage.User, "user")
		ch <- counter(cpuUsageDesc, cpu.TotalUsage.Nice, "nice")
		ch <- counter(cpuUsageDesc, cpu.TotalUsage.System, "system")
		ch <- counter(cpuUsageDesc, cpu.TotalUsage.Idle, "idle")
		ch <- counter(cpuUsageDesc, cpu.TotalUsage.IoWait, "iowait")
		ch <- counter(cpuUsageDesc, cpu.TotalUsage.Irq, "irq")
		ch <- counter(cpuUsageDesc, cpu.TotalUsage.SoftIrq, "softirq")
		ch <- counter(cpuUsageDesc, cpu.TotalUsage.Steal, "steal")
		ch <- gauge(cpuLogicalCoresDesc, float64(cpu.LogicalCores))
	}

	mem, err := memoryInfo(procRoot)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Errorln(err)
		}
	} else {
		ch <- gauge(memTotalDesc, mem.TotalBytes)
		ch <- gauge(memFreeDesc, mem.FreeBytes)
		ch <- gauge(memAvailableDesc, mem.AvailableBytes)
		ch <- gauge(memCacheDesc, mem.CachedBytes)
	}

	disks, err := GetDisks()
	if err != nil {
		klog.Errorln("failed to get disk stats:", err)
	} else {
		for _, d := range disks.BlockDevices() {
			ch <- counter(diskReadsDesc, d.ReadOps, d.Name)
			ch <- counter(diskWritesDesc, d.WriteOps, d.Name)
			ch <- counter(diskReadBytesDesc, d.BytesRead, d.Name)
			ch <- counter(diskWrittenBytesDesc, d.BytesWritten, d.Name)
			ch <- counter(diskReadTimeDesc, d.ReadTimeSeconds, d.Name)
			ch <- counter(diskWriteTimeDesc, d.WriteTimeSeconds, d.Name)
			ch <- counter(diskIoTimeDesc, d.IoTimeSeconds, d.Name)
		}
	}

	netdev, err := NetDevices()
	if err != nil {
		klog.Errorln(err)
	} else {
		for _, dev := range netdev {
			ch <- counter(netRxBytesDesc, dev.RxBytes, dev.Name)
			ch <- counter(netTxBytesDesc, dev.TxBytes, dev.Name)
			ch <- counter(netRxPacketsDesc, dev.RxPackets, dev.Name)
			ch <- counter(netTxPacketsDesc, dev.TxPackets, dev.Name)
			ch <- gauge(netIfaceUpDesc, dev.Up, dev.Name)
			for _, p := range dev.IPPrefixes {
				ch <- gauge(ipDesc, 1, dev.Name, p.IP().String())
			}
		}
	}

	im := metadata.CloudMetadata{}
	if c.instanceMetadata != nil {
		im = *c.instanceMetadata
	}
	if f := flags.GetString(flags.Provider); f != "" {
		im.Provider = metadata.CloudProvider(f)
	}
	if f := flags.GetString(flags.Region); f != "" {
		im.Region = f
	}
	if f := flags.GetString(flags.AvailabilityZone); f != "" {
		im.AvailabilityZone = f
	}
	if f := flags.GetString(flags.InstanceType); f != "" {
		im.InstanceType = f
	}
	if f := flags.GetString(flags.InstanceLifeCycle); f != "" {
		im.LifeCycle = f
	}
	ch <- gauge(cloudInfoDesc, 1,
		string(im.Provider), im.AccountId, im.InstanceId, im.InstanceType, im.LifeCycle,
		im.Region, im.AvailabilityZone, im.AvailabilityZoneId, im.LocalIPv4, im.PublicIPv4,
	)
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- infoDesc
	ch <- cloudInfoDesc
	ch <- uptimeDesc
	ch <- cpuUsageDesc
	ch <- cpuLogicalCoresDesc
	ch <- memTotalDesc
	ch <- memFreeDesc
	ch <- memAvailableDesc
	ch <- memCacheDesc
	ch <- diskReadsDesc
	ch <- diskWritesDesc
	ch <- diskReadBytesDesc
	ch <- diskWrittenBytesDesc
	ch <- diskReadTimeDesc
	ch <- diskWriteTimeDesc
	ch <- diskIoTimeDesc
	ch <- netRxBytesDesc
	ch <- netTxBytesDesc
	ch <- netRxPacketsDesc
	ch <- netTxPacketsDesc
	ch <- netIfaceUpDesc
	ch <- ipDesc
}

func counter(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, labelValues...)
}

func gauge(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labelValues...)
}
