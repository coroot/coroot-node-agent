//go:build windows

package containers

import (
	"time"

	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
)

type ContainerID string

type ProcessInfo struct {
	Pid         uint32
	ContainerId ContainerID
	StartedAt   time.Time
	Flags       proc.Flags
}

type Registry struct{}

func NewRegistry(reg prometheus.Registerer, processInfoCh chan<- ProcessInfo, profilingUpdateCh chan *ProfilingUpdate, gpuProcessUsageSampleChan chan gpu.ProcessUsageSample) (*Registry, error) {
	return &Registry{}, nil
}

func (r *Registry) Describe(ch chan<- *prometheus.Desc) {}

func (r *Registry) Collect(ch chan<- prometheus.Metric) {}

func (r *Registry) Close() {}

const (
	RuntimeJvm = "jvm"
	RuntimeGo  = "go"
)

type ProfilingUpdate struct {
	Pid             uint32
	Runtime         string
	AllocBytes      int64
	AllocObjects    int64
	LockContentions int64
	LockTimeNs      int64
}
