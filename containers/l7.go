package containers

import (
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

type L7Metrics struct {
	Requests *prometheus.CounterVec
	Latency  prometheus.Histogram
}

func (m *L7Metrics) observe(status, method string, duration time.Duration) {
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
		protoStats[key] = m
		constLabels := map[string]string{"destination": key.DestinationLabelValue(), "actual_destination": key.ActualDestinationLabelValue()}
		labels := []string{"status"}
		switch protocol {
		case l7.ProtocolRabbitmq, l7.ProtocolNats:
			labels = append(labels, "method")
		default:
			hOpts := L7Latency[protocol]
			m.Latency = prometheus.NewHistogram(
				prometheus.HistogramOpts{Name: hOpts.Name, Help: hOpts.Help, ConstLabels: constLabels},
			)
		}
		cOpts := L7Requests[protocol]
		m.Requests = prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: cOpts.Name, Help: cOpts.Help, ConstLabels: constLabels}, labels,
		)
	}
	return m
}

func (s L7Stats) collect(ch chan<- prometheus.Metric) {
	for _, protoStats := range s {
		for _, m := range protoStats {
			if m.Requests != nil {
				m.Requests.Collect(ch)
			}
			if m.Latency != nil {
				m.Latency.Collect(ch)
			}
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
