package node

import (
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func (c *Collector) sysfsRoot() string {
	if c.SysfsRoot == "" {
		return defaultSysfsRoot
	}
	return c.SysfsRoot
}

// collectRdma exposes what node_exporter does not: the device to PCI address and net device mapping and every vendor
// hardware counter. Port state, rate and standard counters are left to node_exporter (node_infiniband_*).
func (c *Collector) collectRdma(ch chan<- prometheus.Metric) {
	for _, d := range rdmaDevices(c.sysfsRoot()) {
		ch <- metrics.Gauge(metrics.NodeRdmaDeviceInfo, 1, d.Name, d.PciAddress, d.Netdev, d.FwVersion)
		for _, p := range d.Ports {
			for name, v := range p.HwCounters {
				ch <- metrics.Counter(metrics.NodeRdmaHwCounter, v, d.Name, p.Number, name)
			}
		}
	}
}

// collectPcie exposes the AER error counters, which node_exporter's pcidevice collector does not export. Link speed and
// width are left to node_exporter (node_pcidevice_*).
func (c *Collector) collectPcie(ch chan<- prometheus.Metric) {
	for _, d := range pcieDevices(c.sysfsRoot()) {
		for severity, errs := range d.AerErrors {
			for name, v := range errs {
				ch <- metrics.Counter(metrics.NodePcieAerErrors, v, d.Address, severity, name)
			}
		}
	}
}
