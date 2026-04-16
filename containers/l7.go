package containers

import (
	"fmt"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
)

var defaultBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

type l7DescCache struct {
	requests           *prometheus.Desc
	requestsWithMethod *prometheus.Desc
	latency            *prometheus.Desc
	latencySum         *prometheus.Desc
	latencyCount       *prometheus.Desc
}

var l7Descs map[l7.Protocol]*l7DescCache
var dnsDescs struct {
	requests     *prometheus.Desc
	latency      *prometheus.Desc
	latencySum   *prometheus.Desc
	latencyCount *prometheus.Desc
}

func init() {
	l7Descs = make(map[l7.Protocol]*l7DescCache, len(L7Requests))
	for proto, opts := range L7Requests {
		l7Descs[proto] = &l7DescCache{
			requests:           prometheus.NewDesc(opts.Name, opts.Help, []string{"destination", "actual_destination", "status"}, nil),
			requestsWithMethod: prometheus.NewDesc(opts.Name, opts.Help, []string{"destination", "actual_destination", "status", "method"}, nil),
		}
		if latOpts, ok := L7Latency[proto]; ok {
			l7Descs[proto].latency = prometheus.NewDesc(latOpts.Name, latOpts.Help, []string{"destination", "actual_destination", "le"}, nil)
			l7Descs[proto].latencySum = prometheus.NewDesc(latOpts.Name+"_sum", latOpts.Help, []string{"destination", "actual_destination"}, nil)
			l7Descs[proto].latencyCount = prometheus.NewDesc(latOpts.Name+"_count", latOpts.Help, []string{"destination", "actual_destination"}, nil)
		}
	}
	if opts, ok := L7Requests[l7.ProtocolDNS]; ok {
		dnsDescs.requests = prometheus.NewDesc(opts.Name, opts.Help, []string{"request_type", "domain", "status"}, nil)
	}
	if latOpts, ok := L7Latency[l7.ProtocolDNS]; ok {
		dnsDescs.latency = prometheus.NewDesc(latOpts.Name, latOpts.Help, []string{"le"}, nil)
		dnsDescs.latencySum = prometheus.NewDesc(latOpts.Name+"_sum", latOpts.Help, nil, nil)
		dnsDescs.latencyCount = prometheus.NewDesc(latOpts.Name+"_count", latOpts.Help, nil, nil)
	}
}

type requestCounter struct {
	status string
	method string
	count  uint64
}

type lightweightHistogram struct {
	bucketCounts []uint64
	sum          float64
	count        uint64
}

func newLightweightHistogram() *lightweightHistogram {
	return &lightweightHistogram{
		bucketCounts: make([]uint64, len(defaultBuckets)),
	}
}

func (h *lightweightHistogram) observe(v float64) {
	h.sum += v
	h.count++
	for i, upper := range defaultBuckets {
		if v <= upper {
			h.bucketCounts[i]++
		}
	}
}

type L7Metrics struct {
	requests []requestCounter
	latency  *lightweightHistogram
}

func (m *L7Metrics) observe(status, method string, duration time.Duration) {
	for i := range m.requests {
		if m.requests[i].status == status && m.requests[i].method == method {
			m.requests[i].count++
			if m.latency != nil && duration != 0 {
				m.latency.observe(duration.Seconds())
			}
			return
		}
	}
	m.requests = append(m.requests, requestCounter{status: status, method: method, count: 1})
	if m.latency != nil && duration != 0 {
		m.latency.observe(duration.Seconds())
	}
}

type L7Stats map[l7.Protocol]map[common.DestinationKey]*L7Metrics

func (s L7Stats) get(protocol l7.Protocol, key common.DestinationKey) *L7Metrics {
	if protocol == l7.ProtocolHTTP2 {
		protocol = l7.ProtocolHTTP
	}
	protoStats := s[protocol]
	if protoStats == nil {
		protoStats = map[common.DestinationKey]*L7Metrics{}
		s[protocol] = protoStats
	}
	m := protoStats[key]
	if m == nil {
		m = &L7Metrics{}
		switch protocol {
		case l7.ProtocolRabbitmq, l7.ProtocolNats:
		default:
			m.latency = newLightweightHistogram()
		}
		protoStats[key] = m
	}
	return m
}

func (s L7Stats) collect(ch chan<- prometheus.Metric) {
	for protocol, protoStats := range s {
		descs, ok := l7Descs[protocol]
		if !ok {
			continue
		}
		hasLatency := descs.latency != nil

		for key, m := range protoStats {
			dest := key.DestinationLabelValue()
			act := key.ActualDestinationLabelValue()
			for _, rc := range m.requests {
				if rc.method != "" {
					ch <- prometheus.MustNewConstMetric(
						descs.requestsWithMethod,
						prometheus.CounterValue, float64(rc.count), dest, act, rc.status, rc.method,
					)
				} else {
					ch <- prometheus.MustNewConstMetric(
						descs.requests,
						prometheus.CounterValue, float64(rc.count), dest, act, rc.status,
					)
				}
			}
			if hasLatency && m.latency != nil {
				emitHistogram(ch, descs, dest, act, m.latency)
			}
		}
	}
}

func emitHistogram(ch chan<- prometheus.Metric, descs *l7DescCache, dest, act string, h *lightweightHistogram) {
	for i, upper := range defaultBuckets {
		ch <- prometheus.MustNewConstMetric(descs.latency, prometheus.CounterValue, float64(h.bucketCounts[i]), dest, act, sortFloatStr(upper))
	}
	ch <- prometheus.MustNewConstMetric(descs.latency, prometheus.CounterValue, float64(h.bucketCounts[len(defaultBuckets)-1]), dest, act, "+Inf")
	ch <- prometheus.MustNewConstMetric(descs.latencySum, prometheus.CounterValue, h.sum, dest, act)
	ch <- prometheus.MustNewConstMetric(descs.latencyCount, prometheus.CounterValue, float64(h.count), dest, act)
}

func sortFloatStr(v float64) string {
	return fmt.Sprintf("%g", v)
}

func (s L7Stats) delete(dst common.HostPort) {
	for _, protoStats := range s {
		for d := range protoStats {
			if d.Destination() == dst {
				delete(protoStats, d)
			}
		}
	}
}

type dnsCounter struct {
	requestType string
	domain      string
	status      string
	count       uint64
}

type DnsStats struct {
	requests []dnsCounter
	latency  *lightweightHistogram
}

func (d *DnsStats) observe(t, fqdn, status string) {
	for i := range d.requests {
		if d.requests[i].requestType == t && d.requests[i].domain == fqdn && d.requests[i].status == status {
			d.requests[i].count++
			return
		}
	}
	d.requests = append(d.requests, dnsCounter{requestType: t, domain: fqdn, status: status, count: 1})
}

func (d *DnsStats) observeLatency(seconds float64) {
	if d.latency == nil {
		d.latency = newLightweightHistogram()
	}
	d.latency.observe(seconds)
}

func (d *DnsStats) collect(ch chan<- prometheus.Metric) {
	for _, rc := range d.requests {
		ch <- prometheus.MustNewConstMetric(
			dnsDescs.requests,
			prometheus.CounterValue, float64(rc.count), rc.requestType, rc.domain, rc.status,
		)
	}
	if d.latency != nil {
		emitHistogramDNS(ch, d.latency)
	}
}

func emitHistogramDNS(ch chan<- prometheus.Metric, h *lightweightHistogram) {
	for i, upper := range defaultBuckets {
		ch <- prometheus.MustNewConstMetric(dnsDescs.latency, prometheus.CounterValue, float64(h.bucketCounts[i]), sortFloatStr(upper))
	}
	ch <- prometheus.MustNewConstMetric(dnsDescs.latency, prometheus.CounterValue, float64(h.bucketCounts[len(defaultBuckets)-1]), "+Inf")
	ch <- prometheus.MustNewConstMetric(dnsDescs.latencySum, prometheus.CounterValue, h.sum)
	ch <- prometheus.MustNewConstMetric(dnsDescs.latencyCount, prometheus.CounterValue, float64(h.count))
}
