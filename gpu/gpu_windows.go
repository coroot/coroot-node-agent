//go:build windows

package gpu

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Collector struct {
	ProcessUsageSampleCh chan ProcessUsageSample
}

type ProcessUsageSample struct {
	UUID          string
	Pid           uint32
	Timestamp     time.Time
	GPUPercent    uint32
	MemoryPercent uint32
}

func NewCollector() (*Collector, error) {
	return &Collector{
		ProcessUsageSampleCh: make(chan ProcessUsageSample, 100),
	}, nil
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {}
