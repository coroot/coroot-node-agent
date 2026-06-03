package gpu

import (
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/windows"
	"k8s.io/klog/v2"
)

const (
	nvmlSuccess = 0
)

const (
	nvmlTemperatureGpu = 0
)

type nvmlMemory struct {
	Total uint64
	Free  uint64
	Used  uint64
}

type nvmlUtilization struct {
	Gpu    uint32
	Memory uint32
}

type nvmlCollector struct {
	dll           *windows.LazyDLL
	devices       []nvmlDevice
	driverVersion string
	lock          sync.Mutex
}

type nvmlDevice struct {
	handle uintptr
	uuid   string
	name   string
}

func DefaultLibPaths() []string {
	return []string{
		`C:\Windows\System32\nvml.dll`,
		`C:\Program Files\NVIDIA Corporation\NVSMI\nvml.dll`,
	}
}

func NewCollector(opts Options) (*Collector, error) {
	c := &Collector{}
	if opts.Disabled {
		return c, nil
	}

	libPath := ""
	for _, p := range opts.LibPaths {
		if _, err := os.Stat(p); err == nil {
			libPath = p
			break
		}
	}
	if libPath == "" {
		klog.Infoln("NVML library not found in known paths")
		return c, nil
	}
	klog.Infof("found NVML lib at %s", libPath)

	dll := windows.NewLazyDLL(libPath)
	if err := dll.Load(); err != nil {
		klog.Warningf("failed to load NVML: %v", err)
		return c, nil
	}

	proc := dll.NewProc("nvmlInit_v2")
	ret, _, _ := proc.Call()
	if ret != nvmlSuccess {
		klog.Warningf("nvmlInit_v2 failed: %d", ret)
		return c, nil
	}

	driverVersion := make([]byte, 96)
	proc = dll.NewProc("nvmlSystemGetDriverVersion")
	ret, _, _ = proc.Call(uintptr(unsafe.Pointer(&driverVersion[0])), 96)
	driverStr := ""
	if ret == nvmlSuccess {
		driverStr = cstring(driverVersion)
		klog.Infof("NVIDIA driver version: %s", driverStr)
	}

	var count uint32
	proc = dll.NewProc("nvmlDeviceGetCount_v2")
	ret, _, _ = proc.Call(uintptr(unsafe.Pointer(&count)))
	if ret != nvmlSuccess {
		klog.Warningf("nvmlDeviceGetCount_v2 failed: %d", ret)
		return c, nil
	}

	nc := &nvmlCollector{
		dll:           dll,
		driverVersion: driverStr,
	}

	var names []string
	for i := uint32(0); i < count; i++ {
		var handle uintptr
		proc = dll.NewProc("nvmlDeviceGetHandleByIndex_v2")
		ret, _, _ = proc.Call(uintptr(i), uintptr(unsafe.Pointer(&handle)))
		if ret != nvmlSuccess {
			continue
		}

		uuid := make([]byte, 96)
		proc = dll.NewProc("nvmlDeviceGetUUID")
		ret, _, _ = proc.Call(handle, uintptr(unsafe.Pointer(&uuid[0])), 96)
		uuidStr := ""
		if ret == nvmlSuccess {
			uuidStr = cstring(uuid)
		}

		name := make([]byte, 96)
		proc = dll.NewProc("nvmlDeviceGetName")
		ret, _, _ = proc.Call(handle, uintptr(unsafe.Pointer(&name[0])), 96)
		nameStr := ""
		if ret == nvmlSuccess {
			nameStr = cstring(name)
		}

		names = append(names, nameStr)
		nc.devices = append(nc.devices, nvmlDevice{handle: handle, uuid: uuidStr, name: nameStr})
	}
	if len(names) > 0 {
		klog.Infof("found %d GPU: %s", len(names), strings.Join(names, ", "))
	}

	c.impl = nc
	return c, nil
}

func (nc *nvmlCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.NodeGpuInfo
	ch <- metrics.NodeGpuMemoryTotal
	ch <- metrics.NodeGpuMemoryUsed
	ch <- metrics.NodeGpuMemoryUsageAvg
	ch <- metrics.NodeGpuMemoryUsagePeak
	ch <- metrics.NodeGpuUsageAvg
	ch <- metrics.NodeGpuUsagePeak
	ch <- metrics.NodeGpuTemperature
	ch <- metrics.NodeGpuPowerWatts
}

func (nc *nvmlCollector) Collect(ch chan<- prometheus.Metric) {
	if nc.dll == nil {
		return
	}
	nc.lock.Lock()
	defer nc.lock.Unlock()

	for _, dev := range nc.devices {
		ch <- metrics.Gauge(metrics.NodeGpuInfo, 1, dev.uuid, dev.name, nc.driverVersion)

		var mem nvmlMemory
		proc := nc.dll.NewProc("nvmlDeviceGetMemoryInfo")
		ret, _, _ := proc.Call(dev.handle, uintptr(unsafe.Pointer(&mem)))
		if ret == nvmlSuccess {
			ch <- metrics.Gauge(metrics.NodeGpuMemoryTotal, float64(mem.Total), dev.uuid)
			ch <- metrics.Gauge(metrics.NodeGpuMemoryUsed, float64(mem.Used), dev.uuid)
		}

		var temp uint32
		proc = nc.dll.NewProc("nvmlDeviceGetTemperature")
		ret, _, _ = proc.Call(dev.handle, uintptr(nvmlTemperatureGpu), uintptr(unsafe.Pointer(&temp)))
		if ret == nvmlSuccess {
			ch <- metrics.Gauge(metrics.NodeGpuTemperature, float64(temp), dev.uuid)
		}

		var power uint32
		proc = nc.dll.NewProc("nvmlDeviceGetPowerUsage")
		ret, _, _ = proc.Call(dev.handle, uintptr(unsafe.Pointer(&power)))
		if ret == nvmlSuccess {
			ch <- metrics.Gauge(metrics.NodeGpuPowerWatts, float64(power)/1000.0, dev.uuid)
		}

		var util nvmlUtilization
		proc = nc.dll.NewProc("nvmlDeviceGetUtilizationRates")
		ret, _, _ = proc.Call(dev.handle, uintptr(unsafe.Pointer(&util)))
		if ret == nvmlSuccess {
			ch <- metrics.Gauge(metrics.NodeGpuUsageAvg, float64(util.Gpu), dev.uuid)
			ch <- metrics.Gauge(metrics.NodeGpuUsagePeak, float64(util.Gpu), dev.uuid)
			ch <- metrics.Gauge(metrics.NodeGpuMemoryUsageAvg, float64(util.Memory), dev.uuid)
			ch <- metrics.Gauge(metrics.NodeGpuMemoryUsagePeak, float64(util.Memory), dev.uuid)
		}
	}
}

func (nc *nvmlCollector) Close() {
	proc := nc.dll.NewProc("nvmlShutdown")
	proc.Call()
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
