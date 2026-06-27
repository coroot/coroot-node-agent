//go:build linux

package gpu

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

typedef void* coroot_nvml_device_t;
typedef int coroot_nvml_return_t;
typedef int coroot_nvml_sampling_type_t;
typedef int coroot_nvml_value_type_t;

typedef struct {
	uint64_t total;
	uint64_t free;
	uint64_t used;
} coroot_nvml_memory_t;

typedef struct {
	uint64_t timeStamp;
	uint8_t sampleValue[8];
} coroot_nvml_sample_t;

typedef struct {
	uint32_t pid;
	uint64_t timeStamp;
	uint32_t smUtil;
	uint32_t memUtil;
	uint32_t encUtil;
	uint32_t decUtil;
} coroot_nvml_process_utilization_sample_t;

typedef coroot_nvml_return_t (*nvmlInit_v2_t)(void);
typedef coroot_nvml_return_t (*nvmlShutdown_t)(void);
typedef const char* (*nvmlErrorString_t)(coroot_nvml_return_t);
typedef coroot_nvml_return_t (*nvmlSystemGetDriverVersion_t)(char*, unsigned int);
typedef coroot_nvml_return_t (*nvmlDeviceGetCount_v2_t)(unsigned int*);
typedef coroot_nvml_return_t (*nvmlDeviceGetHandleByIndex_v2_t)(unsigned int, coroot_nvml_device_t*);
typedef coroot_nvml_return_t (*nvmlDeviceGetUUID_t)(coroot_nvml_device_t, char*, unsigned int);
typedef coroot_nvml_return_t (*nvmlDeviceGetName_t)(coroot_nvml_device_t, char*, unsigned int);
typedef coroot_nvml_return_t (*nvmlDeviceGetMemoryInfo_t)(coroot_nvml_device_t, coroot_nvml_memory_t*);
typedef coroot_nvml_return_t (*nvmlDeviceGetTemperature_t)(coroot_nvml_device_t, unsigned int, unsigned int*);
typedef coroot_nvml_return_t (*nvmlDeviceGetPowerUsage_t)(coroot_nvml_device_t, unsigned int*);
typedef coroot_nvml_return_t (*nvmlDeviceGetSamples_t)(coroot_nvml_device_t, coroot_nvml_sampling_type_t, unsigned long long, coroot_nvml_value_type_t*, unsigned int*, coroot_nvml_sample_t*);
typedef coroot_nvml_return_t (*nvmlDeviceGetProcessUtilization_t)(coroot_nvml_device_t, coroot_nvml_process_utilization_sample_t*, unsigned int*, unsigned long long);

static void* coroot_dlopen(const char* path) { return dlopen(path, RTLD_LAZY | RTLD_LOCAL); }
static void* coroot_dlsym(void* handle, const char* name) { return dlsym(handle, name); }
static const char* coroot_dlerror() { return dlerror(); }
static int coroot_dlclose(void* handle) { return dlclose(handle); }

static coroot_nvml_return_t call_nvmlInit_v2(void* f) { return ((nvmlInit_v2_t)f)(); }
static coroot_nvml_return_t call_nvmlShutdown(void* f) { return ((nvmlShutdown_t)f)(); }
static const char* call_nvmlErrorString(void* f, coroot_nvml_return_t ret) { return ((nvmlErrorString_t)f)(ret); }
static coroot_nvml_return_t call_nvmlSystemGetDriverVersion(void* f, char* version, unsigned int length) { return ((nvmlSystemGetDriverVersion_t)f)(version, length); }
static coroot_nvml_return_t call_nvmlDeviceGetCount_v2(void* f, unsigned int* count) { return ((nvmlDeviceGetCount_v2_t)f)(count); }
static coroot_nvml_return_t call_nvmlDeviceGetHandleByIndex_v2(void* f, unsigned int index, void* device) { return ((nvmlDeviceGetHandleByIndex_v2_t)f)(index, (coroot_nvml_device_t*)device); }
static coroot_nvml_return_t call_nvmlDeviceGetUUID(void* f, coroot_nvml_device_t device, char* uuid, unsigned int length) { return ((nvmlDeviceGetUUID_t)f)(device, uuid, length); }
static coroot_nvml_return_t call_nvmlDeviceGetName(void* f, coroot_nvml_device_t device, char* name, unsigned int length) { return ((nvmlDeviceGetName_t)f)(device, name, length); }
static coroot_nvml_return_t call_nvmlDeviceGetMemoryInfo(void* f, coroot_nvml_device_t device, void* memory) { return ((nvmlDeviceGetMemoryInfo_t)f)(device, (coroot_nvml_memory_t*)memory); }
static coroot_nvml_return_t call_nvmlDeviceGetTemperature(void* f, coroot_nvml_device_t device, unsigned int sensorType, unsigned int* temperature) { return ((nvmlDeviceGetTemperature_t)f)(device, sensorType, temperature); }
static coroot_nvml_return_t call_nvmlDeviceGetPowerUsage(void* f, coroot_nvml_device_t device, unsigned int* power) { return ((nvmlDeviceGetPowerUsage_t)f)(device, power); }
static coroot_nvml_return_t call_nvmlDeviceGetSamples(void* f, coroot_nvml_device_t device, coroot_nvml_sampling_type_t type, unsigned long long lastSeenTimeStamp, coroot_nvml_value_type_t* sampleValType, unsigned int* sampleCount, void* samples) { return ((nvmlDeviceGetSamples_t)f)(device, type, lastSeenTimeStamp, sampleValType, sampleCount, (coroot_nvml_sample_t*)samples); }
static coroot_nvml_return_t call_nvmlDeviceGetProcessUtilization(void* f, coroot_nvml_device_t device, void* utilization, unsigned int* processSamplesCount, unsigned long long lastSeenTimeStamp) { return ((nvmlDeviceGetProcessUtilization_t)f)(device, (coroot_nvml_process_utilization_sample_t*)utilization, processSamplesCount, lastSeenTimeStamp); }
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

const (
	nvmlSuccess               C.coroot_nvml_return_t = 0
	nvmlErrorInsufficientSize C.coroot_nvml_return_t = 7
)

const (
	nvmlTemperatureGPU = 0
)

type nvmlSamplingType int32

const (
	nvmlGPUUtilizationSamples    nvmlSamplingType = 1
	nvmlMemoryUtilizationSamples nvmlSamplingType = 2
)

type nvmlValueType int32

const (
	nvmlValueTypeDouble           nvmlValueType = 0
	nvmlValueTypeUnsignedInt      nvmlValueType = 1
	nvmlValueTypeUnsignedLong     nvmlValueType = 2
	nvmlValueTypeUnsignedLongLong nvmlValueType = 3
	nvmlValueTypeSignedLongLong   nvmlValueType = 4
	nvmlValueTypeSignedInt        nvmlValueType = 5
)

type Collector struct {
	ProcessUsageSampleCh chan ProcessUsageSample
	lib                  *nvmlLibrary
	devices              []*Device
	lock                 sync.Mutex
	stopCh               chan struct{}
	driverVersion        string
}

type Device struct {
	UUID           string
	Name           string
	handle         unsafe.Pointer
	lastSampleTime map[nvmlSamplingType]uint64
}

type ProcessUsageSample struct {
	UUID          string
	Pid           uint32
	Timestamp     time.Time
	GPUPercent    uint32
	MemoryPercent uint32
}

type nvmlMemory struct {
	Total uint64
	Free  uint64
	Used  uint64
}

type nvmlSample struct {
	TimeStamp   uint64
	SampleValue [8]byte
}

type nvmlProcessUtilizationSample struct {
	Pid       uint32
	TimeStamp uint64
	SmUtil    uint32
	MemUtil   uint32
	EncUtil   uint32
	DecUtil   uint32
}

type nvmlLibrary struct {
	handle unsafe.Pointer

	init                        unsafe.Pointer
	shutdown                    unsafe.Pointer
	errorString                 unsafe.Pointer
	systemGetDriverVersion      unsafe.Pointer
	deviceGetCount              unsafe.Pointer
	deviceGetHandleByIndex      unsafe.Pointer
	deviceGetUUID               unsafe.Pointer
	deviceGetName               unsafe.Pointer
	deviceGetMemoryInfo         unsafe.Pointer
	deviceGetTemperature        unsafe.Pointer
	deviceGetPowerUsage         unsafe.Pointer
	deviceGetSamples            unsafe.Pointer
	deviceGetProcessUtilization unsafe.Pointer
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

	lib, err := loadNVML(libPath)
	if err != nil {
		return c, err
	}
	if ret := C.call_nvmlInit_v2(lib.init); ret != nvmlSuccess {
		lib.Close()
		return c, fmt.Errorf("unable to initialize NVML: %s", lib.error(ret))
	}

	var count C.uint
	if ret := C.call_nvmlDeviceGetCount_v2(lib.deviceGetCount, &count); ret != nvmlSuccess {
		lib.shutdownAndClose()
		return c, fmt.Errorf("unable to get device count: %s", lib.error(ret))
	}

	c.lib = lib
	c.driverVersion = lib.driverVersion()

	var names []string
	for i := C.uint(0); i < count; i++ {
		var handle unsafe.Pointer
		ret := C.call_nvmlDeviceGetHandleByIndex_v2(lib.deviceGetHandleByIndex, i, unsafe.Pointer(&handle))
		if ret != nvmlSuccess {
			c.Close()
			return c, fmt.Errorf("unable to get device %d handle: %s", i, lib.error(ret))
		}
		dev := Device{
			lastSampleTime: map[nvmlSamplingType]uint64{},
			handle:         handle,
		}
		dev.UUID = lib.deviceString(lib.deviceGetUUID, handle, 96)
		if dev.UUID == "" {
			c.Close()
			return c, fmt.Errorf("unable to get device %d uuid", i)
		}
		dev.Name = lib.deviceString(lib.deviceGetName, handle, 96)
		if dev.Name == "" {
			c.Close()
			return c, fmt.Errorf("unable to get device %d name", i)
		}
		names = append(names, dev.Name)
		c.devices = append(c.devices, &dev)
	}
	if len(names) > 0 {
		klog.Infof("found %d GPU: %s", len(names), strings.Join(names, ", "))
	}

	if c.lib.deviceGetProcessUtilization != nil && len(c.devices) > 0 {
		c.stopCh = make(chan struct{})
		go c.processUtilizationPoller(c.stopCh)
	}
	return c, nil
}

func loadNVML(path string) (*nvmlLibrary, error) {
	handle, err := dlopen(path)
	if err != nil {
		return nil, fmt.Errorf("load NVML: %w", err)
	}
	lib := &nvmlLibrary{handle: handle}
	defer func() {
		if err != nil {
			lib.Close()
		}
	}()

	required := []struct {
		name string
		dst  *unsafe.Pointer
	}{
		{"nvmlInit_v2", &lib.init},
		{"nvmlShutdown", &lib.shutdown},
		{"nvmlDeviceGetCount_v2", &lib.deviceGetCount},
		{"nvmlDeviceGetHandleByIndex_v2", &lib.deviceGetHandleByIndex},
		{"nvmlDeviceGetUUID", &lib.deviceGetUUID},
		{"nvmlDeviceGetName", &lib.deviceGetName},
	}
	for _, symbol := range required {
		*symbol.dst, err = dlsym(handle, symbol.name)
		if err != nil {
			return nil, err
		}
	}

	lib.errorString, _ = dlsym(handle, "nvmlErrorString")
	lib.systemGetDriverVersion = optionalSymbol(handle, "nvmlSystemGetDriverVersion")
	lib.deviceGetMemoryInfo = optionalSymbol(handle, "nvmlDeviceGetMemoryInfo")
	lib.deviceGetTemperature = optionalSymbol(handle, "nvmlDeviceGetTemperature")
	lib.deviceGetPowerUsage = optionalSymbol(handle, "nvmlDeviceGetPowerUsage")
	lib.deviceGetSamples = optionalSymbol(handle, "nvmlDeviceGetSamples")
	lib.deviceGetProcessUtilization = optionalSymbol(handle, "nvmlDeviceGetProcessUtilization")
	return lib, nil
}

func dlopen(path string) (unsafe.Pointer, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	handle := C.coroot_dlopen(cpath)
	if handle == nil {
		return nil, lastDLError()
	}
	return handle, nil
}

func dlsym(handle unsafe.Pointer, name string) (unsafe.Pointer, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	symbol := C.coroot_dlsym(handle, cname)
	if symbol == nil {
		return nil, fmt.Errorf("%s: %w", name, lastDLError())
	}
	return symbol, nil
}

func optionalSymbol(handle unsafe.Pointer, name string) unsafe.Pointer {
	symbol, err := dlsym(handle, name)
	if err != nil {
		klog.V(2).Infof("optional NVML symbol unavailable: %s", err)
		return nil
	}
	return symbol
}

func lastDLError() error {
	err := C.coroot_dlerror()
	if err == nil {
		return fmt.Errorf("unknown dynamic loader error")
	}
	return fmt.Errorf("%s", C.GoString(err))
}

func (l *nvmlLibrary) Close() {
	if l == nil || l.handle == nil {
		return
	}
	C.coroot_dlclose(l.handle)
	l.handle = nil
}

func (l *nvmlLibrary) shutdownAndClose() {
	if l == nil {
		return
	}
	if l.shutdown != nil {
		C.call_nvmlShutdown(l.shutdown)
	}
	l.Close()
}

func (l *nvmlLibrary) error(ret C.coroot_nvml_return_t) string {
	if l.errorString == nil {
		return fmt.Sprintf("NVML error %d", int(ret))
	}
	msg := C.call_nvmlErrorString(l.errorString, ret)
	if msg == nil {
		return fmt.Sprintf("NVML error %d", int(ret))
	}
	return C.GoString(msg)
}

func (l *nvmlLibrary) driverVersion() string {
	if l.systemGetDriverVersion == nil {
		return ""
	}
	version := make([]byte, 96)
	ret := C.call_nvmlSystemGetDriverVersion(l.systemGetDriverVersion, (*C.char)(unsafe.Pointer(&version[0])), C.uint(len(version)))
	if ret != nvmlSuccess {
		klog.Warningf("nvmlSystemGetDriverVersion failed: %s", l.error(ret))
		return ""
	}
	driverVersion := cstring(version)
	if driverVersion != "" {
		klog.Infof("NVIDIA driver version: %s", driverVersion)
	}
	return driverVersion
}

func (l *nvmlLibrary) deviceString(symbol unsafe.Pointer, handle unsafe.Pointer, size int) string {
	buf := make([]byte, size)
	var ret C.coroot_nvml_return_t
	switch symbol {
	case l.deviceGetUUID:
		ret = C.call_nvmlDeviceGetUUID(symbol, C.coroot_nvml_device_t(handle), (*C.char)(unsafe.Pointer(&buf[0])), C.uint(len(buf)))
	case l.deviceGetName:
		ret = C.call_nvmlDeviceGetName(symbol, C.coroot_nvml_device_t(handle), (*C.char)(unsafe.Pointer(&buf[0])), C.uint(len(buf)))
	default:
		return ""
	}
	if ret != nvmlSuccess {
		klog.Warningf("NVML device string lookup failed: %s", l.error(ret))
		return ""
	}
	return cstring(buf)
}

func (c *Collector) processUtilizationPoller(stopCh <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastTs := uint64(time.Now().UnixMicro())
	for {
		select {
		case <-ticker.C:
			c.collectProcessUtilization(&lastTs)
		case <-stopCh:
			return
		}
	}
}

func (c *Collector) collectProcessUtilization(lastTs *uint64) {
	if c.lib == nil || c.lib.deviceGetProcessUtilization == nil {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, dev := range c.devices {
		samples, ret := c.lib.getProcessUtilization(dev.handle, *lastTs)
		if ret != nvmlSuccess {
			continue
		}
		for _, sample := range samples {
			if sample.TimeStamp <= *lastTs {
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
			*lastTs = sample.TimeStamp
		}
	}
}

func (l *nvmlLibrary) getProcessUtilization(handle unsafe.Pointer, lastSeenTimestamp uint64) ([]nvmlProcessUtilizationSample, C.coroot_nvml_return_t) {
	var count C.uint
	ret := C.call_nvmlDeviceGetProcessUtilization(l.deviceGetProcessUtilization, C.coroot_nvml_device_t(handle), nil, &count, C.ulonglong(lastSeenTimestamp))
	if ret != nvmlErrorInsufficientSize || count == 0 {
		return nil, ret
	}
	samples := make([]nvmlProcessUtilizationSample, int(count))
	ret = C.call_nvmlDeviceGetProcessUtilization(l.deviceGetProcessUtilization, C.coroot_nvml_device_t(handle), unsafe.Pointer(&samples[0]), &count, C.ulonglong(lastSeenTimestamp))
	if int(count) > len(samples) {
		count = C.uint(len(samples))
	}
	return samples[:int(count)], ret
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
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

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if c.lib == nil {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, dev := range c.devices {
		ch <- metrics.Gauge(metrics.NodeGpuInfo, 1, dev.UUID, dev.Name, c.driverVersion)

		if c.lib.deviceGetMemoryInfo != nil {
			var mi nvmlMemory
			ret := C.call_nvmlDeviceGetMemoryInfo(c.lib.deviceGetMemoryInfo, C.coroot_nvml_device_t(dev.handle), unsafe.Pointer(&mi))
			if ret == nvmlSuccess {
				ch <- metrics.Gauge(metrics.NodeGpuMemoryTotal, float64(mi.Total), dev.UUID)
				ch <- metrics.Gauge(metrics.NodeGpuMemoryUsed, float64(mi.Used), dev.UUID)
			}
		}
		if c.lib.deviceGetTemperature != nil {
			var temp C.uint
			ret := C.call_nvmlDeviceGetTemperature(c.lib.deviceGetTemperature, C.coroot_nvml_device_t(dev.handle), C.uint(nvmlTemperatureGPU), &temp)
			if ret == nvmlSuccess {
				ch <- metrics.Gauge(metrics.NodeGpuTemperature, float64(temp), dev.UUID)
			}
		}
		if c.lib.deviceGetPowerUsage != nil {
			var powerMilliwatts C.uint
			ret := C.call_nvmlDeviceGetPowerUsage(c.lib.deviceGetPowerUsage, C.coroot_nvml_device_t(dev.handle), &powerMilliwatts)
			if ret == nvmlSuccess {
				ch <- metrics.Gauge(metrics.NodeGpuPowerWatts, float64(powerMilliwatts)/1000., dev.UUID)
			}
		}
		if c.lib.deviceGetSamples != nil {
			for _, st := range []nvmlSamplingType{nvmlGPUUtilizationSamples, nvmlMemoryUtilizationSamples} {
				lastTs := dev.lastSampleTime[st]
				valtype, samples, ret := c.lib.getSamples(dev.handle, st, lastTs)
				if ret != nvmlSuccess {
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
					case nvmlGPUUtilizationSamples:
						ch <- metrics.Gauge(metrics.NodeGpuUsageAvg, total/count, dev.UUID)
						ch <- metrics.Gauge(metrics.NodeGpuUsagePeak, peak, dev.UUID)
					case nvmlMemoryUtilizationSamples:
						ch <- metrics.Gauge(metrics.NodeGpuMemoryUsageAvg, total/count, dev.UUID)
						ch <- metrics.Gauge(metrics.NodeGpuMemoryUsagePeak, peak, dev.UUID)
					}
				}
				dev.lastSampleTime[st] = lastTs
			}
		}
	}
}

func (l *nvmlLibrary) getSamples(handle unsafe.Pointer, samplingType nvmlSamplingType, lastSeenTimestamp uint64) (nvmlValueType, []nvmlSample, C.coroot_nvml_return_t) {
	var valueType C.coroot_nvml_value_type_t
	var count C.uint
	ret := C.call_nvmlDeviceGetSamples(l.deviceGetSamples, C.coroot_nvml_device_t(handle), C.coroot_nvml_sampling_type_t(samplingType), C.ulonglong(lastSeenTimestamp), &valueType, &count, nil)
	if ret != nvmlSuccess || count == 0 {
		return nvmlValueType(valueType), nil, ret
	}
	samples := make([]nvmlSample, int(count))
	ret = C.call_nvmlDeviceGetSamples(l.deviceGetSamples, C.coroot_nvml_device_t(handle), C.coroot_nvml_sampling_type_t(samplingType), C.ulonglong(lastSeenTimestamp), &valueType, &count, unsafe.Pointer(&samples[0]))
	if int(count) > len(samples) {
		count = C.uint(len(samples))
	}
	return nvmlValueType(valueType), samples[:int(count)], ret
}

func (c *Collector) Close() {
	if c.stopCh != nil {
		close(c.stopCh)
		c.stopCh = nil
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.lib == nil {
		return
	}
	c.lib.shutdownAndClose()
	c.lib = nil
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

func valueToFloat(valueType nvmlValueType, value [8]byte) (float64, error) {
	r := bytes.NewReader(value[:])
	switch valueType {
	case nvmlValueTypeDouble:
		var v float64
		err := binary.Read(r, binary.LittleEndian, &v)
		return v, err
	case nvmlValueTypeUnsignedInt:
		var v uint32
		err := binary.Read(r, binary.LittleEndian, &v)
		return float64(v), err
	case nvmlValueTypeUnsignedLong, nvmlValueTypeUnsignedLongLong:
		var v uint64
		err := binary.Read(r, binary.LittleEndian, &v)
		return float64(v), err
	case nvmlValueTypeSignedLongLong:
		var v int64
		err := binary.Read(r, binary.LittleEndian, &v)
		return float64(v), err
	case nvmlValueTypeSignedInt:
		var v int32
		err := binary.Read(r, binary.LittleEndian, &v)
		return float64(v), err
	default:
		return 0, fmt.Errorf("unsupported value type %d", valueType)
	}
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
