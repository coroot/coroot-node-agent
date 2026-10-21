package containers

import (
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

type L7Metrics struct {
	Requests    *prometheus.CounterVec
	Latency     prometheus.Histogram
	LLM         *L7Metrics
	constLabels prometheus.Labels
}

func (m *L7Metrics) observeLLM(status string, duration time.Duration) {
	if m == nil {
		return
	}
	if m.LLM == nil {
		labels := prometheus.Labels{"type": "llm"}
		for k, v := range m.constLabels {
			labels[k] = v
		}
		m.LLM = newL7Metrics(l7.ProtocolHTTP, L7Requests, L7Latency, labels)
	}
	m.LLM.observe(status, "", duration)
}

func (m *L7Metrics) collect(ch chan<- prometheus.Metric) {
	if m == nil {
		return
	}
	if m.Requests != nil {
		m.Requests.Collect(ch)
	}
	if m.Latency != nil {
		m.Latency.Collect(ch)
	}
	m.LLM.collect(ch)
}

func (m *L7Metrics) observe(status, method string, duration time.Duration) {
	if m == nil {
		return
	}
	if m.Requests != nil {
		var err error
		var c prometheus.Counter
		if method != "" {
			c, err = m.Requests.GetMetricWithLabelValues(status, method)
		} else {
			c, err = m.Requests.GetMetricWithLabelValues(status)
		}
		if err != nil {
			klog.Warningln(err)
		} else {
			c.Inc()
		}
	}
	if m.Latency != nil && duration != 0 {
		m.Latency.Observe(duration.Seconds())
	}
}

type L7Stats map[l7.Protocol]map[common.DestinationKey]*L7Metrics // protocol -> dst:actual_dst -> metrics

func newL7Metrics(protocol l7.Protocol, requests map[l7.Protocol]prometheus.CounterOpts, latency map[l7.Protocol]prometheus.HistogramOpts, constLabels prometheus.Labels) *L7Metrics {
	cOpts, ok := requests[protocol]
	if !ok {
		return nil
	}
	m := &L7Metrics{constLabels: constLabels}
	labels := []string{"status"}
	switch protocol {
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		labels = append(labels, "method")
	default:
		if hOpts, ok := latency[protocol]; ok {
			m.Latency = prometheus.NewHistogram(
				prometheus.HistogramOpts{Name: hOpts.Name, Help: hOpts.Help, ConstLabels: constLabels, Buckets: hOpts.Buckets},
			)
		}
	}
	m.Requests = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: cOpts.Name, Help: cOpts.Help, ConstLabels: constLabels}, labels,
	)
	return m
}

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
		constLabels := prometheus.Labels{"destination": key.DestinationLabelValue(), "actual_destination": key.ActualDestinationLabelValue()}
		if m = newL7Metrics(protocol, L7Requests, L7Latency, constLabels); m == nil {
			return nil
		}
		protoStats[key] = m
	}
	return m
}

func (s L7Stats) collect(ch chan<- prometheus.Metric) {
	for _, protoStats := range s {
		for _, m := range protoStats {
			m.collect(ch)
		}
	}
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

type L7InboundStats map[l7.Protocol]*L7Metrics

func (s L7InboundStats) get(protocol l7.Protocol) *L7Metrics {
	if protocol == l7.ProtocolHTTP2 {
		protocol = l7.ProtocolHTTP
	}
	m := s[protocol]
	if m == nil {
		if m = newL7Metrics(protocol, L7InboundRequests, L7InboundLatency, nil); m == nil {
			return nil
		}
		s[protocol] = m
	}
	return m
}

func (s L7InboundStats) collect(ch chan<- prometheus.Metric) {
	for _, m := range s {
		m.collect(ch)
	}
}
