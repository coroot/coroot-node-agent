package gpu

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Options struct {
	Disabled bool
	LibPaths []string
}

type Collector struct {
	ProcessUsageSampleCh chan ProcessUsageSample
	impl                 collectorImpl
}

type ProcessUsageSample struct {
	UUID          string
	Pid           uint32
	Timestamp     time.Time
	GPUPercent    uint32
	MemoryPercent uint32
}

type collectorImpl interface {
	Describe(chan<- *prometheus.Desc)
	Collect(chan<- prometheus.Metric)
	Close()
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	if c.impl != nil {
		c.impl.Describe(ch)
	}
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if c.impl != nil {
		c.impl.Collect(ch)
	}
}

func (c *Collector) Close() {
	if c.impl != nil {
		c.impl.Close()
	}
}
