package node

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"k8s.io/klog/v2"
)

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ch <- metrics.Gauge(metrics.NodeInfo, 1, c.hostname, c.kernelVersion)

	if up, err := host.Uptime(); err != nil {
		klog.Errorln("failed to get uptime:", err)
	} else {
		ch <- metrics.Gauge(metrics.NodeUptime, float64(up))
	}

	if times, err := cpu.Times(false); err != nil {
		klog.Errorln("failed to get CPU times:", err)
	} else if len(times) > 0 {
		t := times[0]
		ch <- metrics.Counter(metrics.NodeCPUUsage, t.User, "user")
		ch <- metrics.Counter(metrics.NodeCPUUsage, t.System, "system")
		ch <- metrics.Counter(metrics.NodeCPUUsage, t.Idle, "idle")
		ch <- metrics.Gauge(metrics.NodeCPULogicalCores, float64(runtime.NumCPU()))
	}

	if vm, err := mem.VirtualMemory(); err != nil {
		klog.Errorln("failed to get memory info:", err)
	} else {
		ch <- metrics.Gauge(metrics.NodeMemoryTotal, float64(vm.Total))
		ch <- metrics.Gauge(metrics.NodeMemoryFree, float64(vm.Free))
		ch <- metrics.Gauge(metrics.NodeMemoryAvailable, float64(vm.Available))
		ch <- metrics.Gauge(metrics.NodeMemoryCached, float64(vm.Cached))
	}

	if io, err := disk.IOCounters(); err != nil {
		klog.Errorln("failed to get disk stats:", err)
	} else {
		for name, d := range io {
			ch <- metrics.Counter(metrics.NodeDiskReads, float64(d.ReadCount), name)
			ch <- metrics.Counter(metrics.NodeDiskWrites, float64(d.WriteCount), name)
			ch <- metrics.Counter(metrics.NodeDiskReadBytes, float64(d.ReadBytes), name)
			ch <- metrics.Counter(metrics.NodeDiskWrittenBytes, float64(d.WriteBytes), name)
			ch <- metrics.Counter(metrics.NodeDiskReadTime, float64(d.ReadTime), name)
			ch <- metrics.Counter(metrics.NodeDiskWriteTime, float64(d.WriteTime), name)
			ch <- metrics.Counter(metrics.NodeDiskIoTime, float64(d.ReadTime+d.WriteTime), name)
		}
	}

	if ifaces, err := getNetworkInterfaces(); err != nil {
		klog.Errorln("failed to get network interfaces:", err)
	} else {
		for _, iface := range ifaces {
			ch <- metrics.Counter(metrics.NodeNetRxBytes, float64(iface.RxBytes), iface.Name)
			ch <- metrics.Counter(metrics.NodeNetTxBytes, float64(iface.TxBytes), iface.Name)
			ch <- metrics.Counter(metrics.NodeNetRxPackets, float64(iface.RxPackets), iface.Name)
			ch <- metrics.Counter(metrics.NodeNetTxPackets, float64(iface.TxPackets), iface.Name)
			up := float64(0)
			if iface.Up {
				up = 1
			}
			ch <- metrics.Gauge(metrics.NodeNetInterfaceUp, up, iface.Name)
			for _, ip := range iface.IPs {
				ch <- metrics.Gauge(metrics.NodeNetInterfaceIP, 1, iface.Name, ip)
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

func GetHostname() string {
	name, err := os.Hostname()
	if err != nil {
		klog.Warningln("failed to get hostname:", err)
		return "unknown"
	}
	return name
}

func GetOSVersion() string {
	name := ""
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		name, _, _ = k.GetStringValue("ProductName")
		name = strings.TrimSpace(name)
		k.Close()
	}
	vi := windows.RtlGetVersion()
	if vi == nil {
		if name != "" {
			return name
		}
		klog.Warningln("failed to get OS version")
		return "Windows"
	}
	if name == "" {
		name = fmt.Sprintf("Windows %d.%d", vi.MajorVersion, vi.MinorVersion)
	}
	return fmt.Sprintf("%s (Build %d)", name, vi.BuildNumber)
}
