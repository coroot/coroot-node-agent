package gpu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	gpuInfo = prometheus.NewDesc(
		"node_gpu_info",
		"Meta information about the GPU",
		[]string{"gpu_uuid", "name"}, nil,
	)
	gpuMemoryTotal = prometheus.NewDesc(
		"node_resources_gpu_memory_total_bytes",
		"Total memory available on the GPU in bytes",
		[]string{"gpu_uuid"}, nil,
	)
	gpuMemoryUsed = prometheus.NewDesc(
		"node_resources_gpu_memory_used_bytes",
		"GPU memory currently in use in bytes",
		[]string{"gpu_uuid"}, nil,
	)
	gpuMemoryUsageAvg = prometheus.NewDesc(
		"node_resources_gpu_memory_utilization_percent_avg",
		"Average GPU memory utilization (percentage) over the collection interval",
		[]string{"gpu_uuid"}, nil,
	)
	gpuTemperature = prometheus.NewDesc(
		"node_resources_gpu_temperature_celsius",
		"Current temperature of the GPU in Celsius",
		[]string{"gpu_uuid"}, nil,
	)
	gpuPowerWatts = prometheus.NewDesc(
		"node_resources_gpu_power_usage_watts",
		"Current power usage of the GPU in watts",
		[]string{"gpu_uuid"}, nil,
	)
	gpuMemoryUsagePeak = prometheus.NewDesc(
		"node_resources_gpu_memory_utilization_percent_peak",
		"Peak GPU memory utilization (percentage) over the collection interval",
		[]string{"gpu_uuid"}, nil,
	)
	gpuUsageAvg = prometheus.NewDesc(
		"node_resources_gpu_utilization_percent_avg",
		"Average GPU core utilization (percentage) over the collection interval",
		[]string{"gpu_uuid"}, nil,
	)
	gpuUsagePeak = prometheus.NewDesc(
		"node_resources_gpu_utilization_percent_peak",
		"Peak GPU core utilization (percentage) over the collection interval",
		[]string{"gpu_uuid"}, nil,
	)
)

type Collector struct {
	ProcessUsageSampleCh chan ProcessUsageSample
	iface                nvml.Interface
	devices              []*Device
	lock                 sync.Mutex
}

type Device struct {
	UUID           string
	Name           string
	device         nvml.Device
	lastSampleTime map[nvml.SamplingType]uint64
}

type ProcessUsageSample struct {
	UUID          string
	Pid           uint32
	Timestamp     time.Time
	GPUPercent    uint32
	MemoryPercent uint32
}

func NewCollector() (*Collector, error) {
	c := &Collector{
		ProcessUsageSampleCh: make(chan ProcessUsageSample, 100),
	}
	if *flags.DisableGPUMonitoring {
		return c, nil
	}
	libPath, err := findNvidiaMLLib()
	if err != nil {
		klog.Infoln(err)
		return c, nil
	}
	klog.Infof("found NVML lib at %s", libPath)

	c.iface = nvml.New(nvml.WithLibraryPath(libPath))
	if ret := c.iface.Init(); ret != nvml.SUCCESS {
		return c, fmt.Errorf("unable to initialize NVML: %s", nvml.ErrorString(ret))
	}
	count, ret := c.iface.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return c, fmt.Errorf("unable to get device count: %s", nvml.ErrorString(ret))
	}
	var names []string
	for i := 0; i < count; i++ {
		device, ret := c.iface.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return c, errors.New(nvml.ErrorString(ret))
		}
		dev := Device{
			lastSampleTime: map[nvml.SamplingType]uint64{},
			device:         device,
		}
		if dev.UUID, ret = device.GetUUID(); ret != nvml.SUCCESS {
			return c, errors.New(nvml.ErrorString(ret))
		}
		if dev.Name, ret = device.GetName(); ret != nvml.SUCCESS {
			return c, errors.New(nvml.ErrorString(ret))
		}
		names = append(names, dev.Name)
		c.devices = append(c.devices, &dev)
	}
	if len(names) > 0 {
		klog.Infof("found %d GPU: %s", len(names), strings.Join(names, ", "))
	}
	go c.processUtilizationPoller()
	return c, nil
}

func (c *Collector) processUtilizationPoller() {
	ticker := time.NewTicker(1 * time.Second)
	lastTs := uint64(time.Now().UnixMicro())
	for range ticker.C {
		for _, dev := range c.devices {
			samples, _ := dev.device.GetProcessUtilization(lastTs)
			for _, sample := range samples {
				if sample.TimeStamp <= lastTs {
					continue
				}
				if sample.SmUtil > 0 {
					c.ProcessUsageSampleCh <- ProcessUsageSample{
						UUID:          dev.UUID,
						Pid:           sample.Pid,
						GPUPercent:    sample.SmUtil,
						MemoryPercent: sample.MemUtil,
						Timestamp:     time.UnixMicro(int64(sample.TimeStamp)),
					}
				}
				lastTs = sample.TimeStamp
			}
		}
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- gpuInfo
	ch <- gpuMemoryTotal
	ch <- gpuMemoryUsed
	ch <- gpuMemoryUsageAvg
	ch <- gpuMemoryUsagePeak
	ch <- gpuUsageAvg
	ch <- gpuUsagePeak
	ch <- gpuTemperature
	ch <- gpuPowerWatts
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, dev := range c.devices {
		ch <- gauge(gpuInfo, 1, dev.UUID, dev.Name)

		mi, ret := dev.device.GetMemoryInfo()
		if ret == nvml.SUCCESS {
			ch <- gauge(gpuMemoryTotal, float64(mi.Total), dev.UUID)
			ch <- gauge(gpuMemoryUsed, float64(mi.Used), dev.UUID)
		}
		if t, ret := dev.device.GetTemperature(nvml.TEMPERATURE_GPU); ret == nvml.SUCCESS {
			ch <- gauge(gpuTemperature, float64(t), dev.UUID)
		}
		if mw, ret := dev.device.GetPowerUsage(); ret == nvml.SUCCESS {
			ch <- gauge(gpuPowerWatts, float64(mw)/1000., dev.UUID)
		}
		for _, st := range []nvml.SamplingType{nvml.GPU_UTILIZATION_SAMPLES, nvml.MEMORY_UTILIZATION_SAMPLES} {
			lastTs := dev.lastSampleTime[st]
			valtype, samples, ret := dev.device.GetSamples(st, lastTs)
			if ret != nvml.SUCCESS {
				continue
			}
			total := float64(0)
			count := float64(0)
			peak := float64(0)
			for _, sample := range samples {
				if sample.TimeStamp <= lastTs {
					continue
				}
				value, err := valueToFloat(valtype, sample.SampleValue)
				if err != nil {
					continue
				}
				total += value
				if value > peak {
					peak = value
				}
				count++
				lastTs = sample.TimeStamp
			}
			if count > 0 {
				switch st {
				case nvml.GPU_UTILIZATION_SAMPLES:
					ch <- gauge(gpuUsageAvg, total/count, dev.UUID)
					ch <- gauge(gpuUsagePeak, peak, dev.UUID)
				case nvml.MEMORY_UTILIZATION_SAMPLES:
					ch <- gauge(gpuMemoryUsageAvg, total/count, dev.UUID)
					ch <- gauge(gpuMemoryUsagePeak, peak, dev.UUID)
				}
			}
			dev.lastSampleTime[st] = lastTs
		}
	}
}

func (c *Collector) Close() {
	if c.iface == nil {
		return
	}
	c.iface.Shutdown()
}

func findNvidiaMLLib() (string, error) {
	paths := []string{
		// gpu-operator
		"/run/nvidia/driver/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1",
		"/run/nvidia/driver/usr/lib64/libnvidia-ml.so.1",
		"/home/kubernetes/bin/nvidia/lib64/libnvidia-ml.so.1", //GKE

		"/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1",
		"/usr/lib64/libnvidia-ml.so.1",
		"/usr/local/cuda/lib64/libnvidia-ml.so.1",
		"/usr/lib/libnvidia-ml.so.1",
	}
	if runtime.GOARCH == "arm64" {
		paths = append(paths,
			"/usr/lib/aarch64-linux-gnu/libnvidia-ml.so.1",
			"/run/nvidia/driver/usr/lib/aarch64-linux-gnu/libnvidia-ml.so.1",
			"/home/kubernetes/bin/nvidia/lib64-aarch64/libnvidia-ml.so.1", //GKE
		)
	}
	for _, p := range paths {
		if _, err := os.Stat(proc.HostPath(p)); err == nil {
			return proc.HostPath(p), nil
		}
	}
	return "", fmt.Errorf("libnvidia-ml.so.1 not found in known paths")
}

func valueToFloat(valueType nvml.ValueType, value [8]byte) (float64, error) {
	r := bytes.NewReader(value[:])
	switch valueType {
	case nvml.VALUE_TYPE_DOUBLE:
		var v float64
		err := binary.Read(r, binary.LittleEndian, &v)
		return v, err
	case nvml.VALUE_TYPE_UNSIGNED_INT:
		var v uint32
		err := binary.Read(r, binary.LittleEndian, &v)
		return float64(v), err
	case nvml.VALUE_TYPE_UNSIGNED_LONG, nvml.VALUE_TYPE_UNSIGNED_LONG_LONG:
		var v uint64
		err := binary.Read(r, binary.LittleEndian, &v)
		return float64(v), err
	case nvml.VALUE_TYPE_SIGNED_LONG_LONG:
		var v int64
		err := binary.Read(r, binary.LittleEndian, &v)
		return float64(v), err
	case nvml.VALUE_TYPE_SIGNED_INT:
		var v int32
		err := binary.Read(r, binary.LittleEndian, &v)
		return float64(v), err
	default:
		return 0, fmt.Errorf("unsupported value type %d", valueType)
	}
}

func gauge(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labelValues...)
}
