//go:build windows

package containers

import (
	"net/netip"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/coroot/coroot-node-agent/windows/nettracer"
	"github.com/coroot/logparser"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

type Kind string

const (
	KindService Kind = "service"
	KindDocker  Kind = "docker"
)

const (
	logSourceEventLog = "EventLog"
	logSourceStdout   = "stdout/stderr"
)

const minDiskWriteBytes = 1024 * 1024

type Stats struct {
	CPUSeconds     float64
	MemoryRSSBytes uint64
	IOReadBytes    uint64
	IOWriteBytes   uint64
	IOReadOps      uint64
	IOWriteOps     uint64
}

type Container struct {
	lock sync.Mutex

	registry *Registry

	ID           string
	Name         string
	DisplayName  string
	Image        string
	Kind         Kind
	PID          uint32
	PIDs         []uint32
	hostListens  []netip.AddrPort
	ips          []netip.Addr
	hyperv       bool
	StartedAt    time.Time
	RestartCount int64
	shared       bool

	goneAt time.Time

	counters counterState
	stats    *Stats

	logPath    string
	logParsers map[string]*logs.Pipeline
	eventLogCh chan logparser.LogEntry

	dnsRequests *prometheus.CounterVec // container_dns_requests_total{request_type,domain,status}
	dnsLatency  prometheus.Histogram   // container_dns_requests_duration_seconds_total
	seenFQDNs   map[string]struct{}    // bounds the domain label cardinality
}

func (c *Container) active() bool {
	return c.goneAt.IsZero() && c.PID != 0
}

func (c *Container) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("container", "", nil, nil)
}

func (c *Container) Collect(ch chan<- prometheus.Metric) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.shared {
		return
	}

	if minAge := *flags.MinContainerAge; minAge > 0 {
		if c.StartedAt.IsZero() || time.Since(c.StartedAt) < minAge {
			return
		}
	}

	ch <- metrics.Gauge(metrics.ContainerInfo, 1, c.Image, "", "")
	ch <- metrics.Counter(metrics.Restarts, float64(c.RestartCount))

	if !c.active() {
		return
	}

	appTypes := map[string]struct{}{}
	for _, p := range c.PIDs {
		if t := guessApplicationType(p); t != "" {
			appTypes[t] = struct{}{}
		}
	}
	for appType := range appTypes {
		ch <- metrics.Gauge(metrics.ApplicationType, 1, appType)
	}
	if _, ok := appTypes["java"]; ok {
		collectJVMMetrics(ch, c.PIDs)
	}

	if c.updateStats() {
		ch <- metrics.Counter(metrics.CPUUsage, c.stats.CPUSeconds)
		ch <- metrics.Gauge(metrics.MemoryRss, float64(c.stats.MemoryRSSBytes))

		if c.Kind == KindService && c.stats.IOWriteBytes > minDiskWriteBytes {
			device, mountPoint := getProcessDiskAndMount(c.PID)
			if device != "" {
				ch <- metrics.Counter(metrics.DiskReadOps, float64(c.stats.IOReadOps), mountPoint, device, "")
				ch <- metrics.Counter(metrics.DiskWriteOps, float64(c.stats.IOWriteOps), mountPoint, device, "")
				ch <- metrics.Counter(metrics.DiskReadBytes, float64(c.stats.IOReadBytes), mountPoint, device, "")
				ch <- metrics.Counter(metrics.DiskWriteBytes, float64(c.stats.IOWriteBytes), mountPoint, device, "")

				if totalBytes, freeBytes, ok := getVolumeSpace(mountPoint); ok {
					ch <- metrics.Gauge(metrics.DiskSize, float64(totalBytes), mountPoint, device, "")
					ch <- metrics.Gauge(metrics.DiskUsed, float64(totalBytes-freeBytes), mountPoint, device, "")
				}
			}
		}
	}

	for _, ap := range c.hostListens {
		for _, s := range expandListen(ap.Addr(), ap.Port(), hostIPs()) {
			ch <- metrics.Gauge(metrics.NetListenInfo, 1, s, "dockerd")
		}
	}

	if c.hyperv {
		for _, ip := range c.ips {
			ch <- metrics.Gauge(metrics.NetListenInfo, 1, netip.AddrPortFrom(ip, 0).String(), "")
		}
	}

	if c.registry.netTracker != nil {
		if netStats := c.registry.netTracker.GetServiceStats(c.PIDs); netStats != nil {
			listenIPs := hostIPs()
			if c.Kind == KindDocker {
				listenIPs = c.ips
			}
			seenListens := map[string]bool{}
			for _, la := range netStats.ListenAddrs {
				addr, err := netip.ParseAddr(la.Addr)
				if err != nil {
					continue
				}
				for _, s := range expandListen(addr, la.Port, listenIPs) {
					if seenListens[s] {
						continue
					}
					seenListens[s] = true
					ch <- metrics.Gauge(metrics.NetListenInfo, 1, s, "")
				}
			}
			failedByDest := map[string]int64{}
			for _, d := range netStats.Destinations {
				if d.ActiveCount > 0 {
					ch <- metrics.Gauge(metrics.NetConnectionsActive, float64(d.ActiveCount), d.Destination, d.ActualDestination)
				}
				if d.SuccessfulCount > 0 {
					ch <- metrics.Counter(metrics.NetConnectionsSuccessful, float64(d.SuccessfulCount), d.Destination, d.ActualDestination)
				}
				if d.FailedCount > 0 {
					failedByDest[d.Destination] += d.FailedCount
				}
			}
			for dest, count := range failedByDest {
				ch <- metrics.Counter(metrics.NetConnectionsFailed, float64(count), dest)
			}
		}
	}

	for source, p := range c.logParsers {
		for _, lc := range p.Counters() {
			sample := lc.Sample
			if len(sample) > *flags.MaxLabelLength {
				sample = sample[:*flags.MaxLabelLength]
			}
			ch <- metrics.Counter(metrics.LogMessages, float64(lc.Messages), source, lc.Level.String(), lc.Hash, sample)
		}
	}

	if c.dnsRequests != nil {
		c.dnsRequests.Collect(ch)
	}
	if c.dnsLatency != nil {
		c.dnsLatency.Collect(ch)
	}
}

const fqdnOverflowLabel = "~other"

func (c *Container) observeDNS(req *nettracer.DNSRequest) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.dnsRequests == nil {
		c.dnsRequests = prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "container_dns_requests_total", Help: "Total number of outbound DNS requests"},
			[]string{"request_type", "domain", "status"},
		)
		c.dnsLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "container_dns_requests_duration_seconds_total",
			Help: "Histogram of the response time for each outbound DNS request",
		})
		c.seenFQDNs = map[string]struct{}{}
	}

	domain := req.FQDN
	if domain != "" {
		if _, ok := c.seenFQDNs[domain]; !ok {
			if len(c.seenFQDNs) < *flags.MaxFQDNsPerContainer {
				c.seenFQDNs[domain] = struct{}{}
			} else {
				domain = fqdnOverflowLabel
			}
		}
	}
	c.dnsRequests.WithLabelValues(req.Type, domain, req.Status).Inc()
	if req.Duration > 0 {
		c.dnsLatency.Observe(req.Duration.Seconds())
	}
}

func (c *Container) updateStats() bool {
	switch c.Kind {
	case KindDocker:
		var err error
		if c.stats, err = c.registry.docker.stats(c.Name); err != nil {
			return false
		}
	case KindService:
		c.stats = c.serviceStats()
	default:
		return false
	}
	return true
}

func (c *Container) addLogParserLocked(source string, p *logs.Pipeline) {
	if c.logParsers == nil {
		c.logParsers = map[string]*logs.Pipeline{}
	}
	c.logParsers[source] = p
}

func (c *Container) eventLogInput() chan logparser.LogEntry {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.eventLogCh != nil {
		return c.eventLogCh
	}
	ch := make(chan logparser.LogEntry, 100)
	parser := logparser.NewParser(ch, nil, logs.OtelLogEmitter(c.ID), logs.MultilineCollectorTimeout, *flags.LogPatternsPerContainer)
	c.addLogParserLocked(logSourceEventLog, logs.NewPipeline(parser, nil))
	c.eventLogCh = ch
	return ch
}

func (c *Container) startLogTailer() {
	if *flags.DisableLogParsing || c.logPath == "" {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.stopLogParserLocked(logSourceStdout)
	ch := make(chan logparser.LogEntry, 100)
	parser := logparser.NewParser(ch, logparser.DockerJsonDecoder{}, logs.OtelLogEmitter(c.ID), logs.MultilineCollectorTimeout, *flags.LogPatternsPerContainer)
	reader, err := logs.NewTailReader(c.logPath, ch)
	if err != nil {
		parser.Stop()
		klog.Warningf("failed to tail logs of %s: %v", c.ID, err)
		return
	}
	c.addLogParserLocked(logSourceStdout, logs.NewPipeline(parser, reader.Stop))
	klog.Infof("started log tailer for %s: %s", c.ID, c.logPath)
}

func (c *Container) stopLogTailer() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.stopLogParserLocked(logSourceStdout)
}

func (c *Container) stopLogParserLocked(source string) {
	if p := c.logParsers[source]; p != nil {
		p.Stop()
		delete(c.logParsers, source)
		if source == logSourceEventLog {
			c.eventLogCh = nil
		}
	}
}

func (c *Container) closeLogs() {
	c.lock.Lock()
	defer c.lock.Unlock()
	for source := range c.logParsers {
		c.stopLogParserLocked(source)
	}
}
