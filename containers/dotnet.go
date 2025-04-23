package containers

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/proc"
	"github.com/jpillora/backoff"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/pyroscope-io/dotnetdiag"
	"github.com/pyroscope-io/dotnetdiag/nettrace"
	"github.com/pyroscope-io/dotnetdiag/nettrace/typecode"
	"k8s.io/klog/v2"
)

const (
	dotNetDiagnosticTimeout = 500 * time.Millisecond
	dotNetEventInterval     = 5 * time.Second
	provider                = "System.Runtime"
)

type dotNetMetric struct {
	fields map[string]string
	values map[string]float64
}

func (m *dotNetMetric) value() float64 {
	switch m.fields["CounterType"] {
	case "Sum":
		return m.values["Increment"]
	case "Mean":
		return m.values["Mean"]
	}
	return math.NaN()
}

func (m *dotNetMetric) name() string {
	return m.fields["Name"]
}

func (m *dotNetMetric) units() string {
	return m.fields["DisplayUnits"]
}

type DotNetMonitor struct {
	pid            uint32
	appName        string
	cancel         context.CancelFunc
	lastUpdate     time.Time
	runtimeVersion string

	info                          *prometheus.GaugeVec
	memoryAllocatedBytes          prometheus.Counter
	exceptionCount                prometheus.Gauge
	heapSize                      *prometheus.GaugeVec
	gcCount                       *prometheus.CounterVec
	heapFragmentationPercent      prometheus.Gauge
	monitorLockContentionCount    prometheus.Counter
	threadPoolCompletedItemsCount prometheus.Counter
	threadPoolQueueLength         prometheus.Gauge
	threadPoolThreadsCount        prometheus.Gauge
}

func NewDotNetMonitor(ctx context.Context, pid uint32, appName string) *DotNetMonitor {
	klog.Infof("starting DotNetMonitor: pid=%d, app=%s", pid, appName)
	constLabels := prometheus.Labels{"application": appName}

	m := &DotNetMonitor{
		pid:                           pid,
		appName:                       appName,
		info:                          newGaugeVec("container_dotnet_info", "Meta information about the Common Language Runtime (CLR)", constLabels, "runtime_version"),
		memoryAllocatedBytes:          newCounter("container_dotnet_memory_allocated_bytes_total", "The number of bytes allocated", constLabels),
		exceptionCount:                newGauge("container_dotnet_exceptions_total", "The number of exceptions that have occurred", constLabels),
		heapSize:                      newGaugeVec("container_dotnet_memory_heap_size_bytes", "Total size of the heap generation in bytes", constLabels, "generation"),
		gcCount:                       newCounterVec("container_dotnet_gc_count_total", "The number of times GC has occurred for the generation", constLabels, "generation"),
		heapFragmentationPercent:      newGauge("container_dotnet_heap_fragmentation_percent", "The heap fragmentation", constLabels),
		monitorLockContentionCount:    newCounter("container_dotnet_monitor_lock_contentions_total", "The number of times there was contention when trying to take the monitor's lock", constLabels),
		threadPoolCompletedItemsCount: newCounter("container_dotnet_thread_pool_completed_items_total", "The number of work items that have been processed in the ThreadPool", constLabels),
		threadPoolQueueLength:         newGauge("container_dotnet_thread_pool_queue_length", "The number of work items that are currently queued to be processed in the ThreadPool", constLabels),
		threadPoolThreadsCount:        newGauge("container_dotnet_thread_pool_size", "The number of thread pool threads that currently exist in the ThreadPool", constLabels),
	}
	go m.run(ctx)
	return m
}

func (m *DotNetMonitor) AppName() string {
	return m.appName
}

func (m *DotNetMonitor) Collect(ch chan<- prometheus.Metric) {
	if m.lastUpdate.Before(time.Now().Add(-2 * dotNetEventInterval)) {
		return
	}
	m.info.Collect(ch)
	m.memoryAllocatedBytes.Collect(ch)
	m.exceptionCount.Collect(ch)
	m.heapSize.Collect(ch)
	m.gcCount.Collect(ch)
	m.heapFragmentationPercent.Collect(ch)
	m.monitorLockContentionCount.Collect(ch)
	m.threadPoolCompletedItemsCount.Collect(ch)
	m.threadPoolQueueLength.Collect(ch)
	m.threadPoolThreadsCount.Collect(ch)
}

func (m *DotNetMonitor) processMetric(name, units string, v float64) {
	m.lastUpdate = time.Now()
	if math.IsNaN(v) {
		return
	}
	switch units {
	case "MB":
		v *= 1000 * 1000
	}
	switch name {
	case "alloc-rate":
		m.memoryAllocatedBytes.Add(v)
	case "exception-count":
		m.exceptionCount.Set(v)
	case "gen-0-gc-count":
		m.gcCount.WithLabelValues("Gen0").Add(v)
	case "gen-1-gc-count":
		m.gcCount.WithLabelValues("Gen1").Add(v)
	case "gen-2-gc-count":
		m.gcCount.WithLabelValues("Gen2").Add(v)
	case "gen-0-size":
		m.heapSize.WithLabelValues("Gen0").Set(v)
	case "gen-1-size":
		m.heapSize.WithLabelValues("Gen1").Set(v)
	case "gen-2-size":
		m.heapSize.WithLabelValues("Gen2").Set(v)
	case "loh-size":
		m.heapSize.WithLabelValues("LOH").Set(v)
	case "poh-size":
		m.heapSize.WithLabelValues("POH").Set(v)
	case "gc-fragmentation":
		m.heapFragmentationPercent.Set(v)
	case "monitor-lock-contention-count":
		m.monitorLockContentionCount.Add(v)
	case "threadpool-completed-items-count":
		m.threadPoolCompletedItemsCount.Add(v)
	case "threadpool-queue-length":
		m.threadPoolQueueLength.Set(v)
	case "threadpool-thread-count":
		m.threadPoolThreadsCount.Set(v)
	}
}

func (m *DotNetMonitor) run(ctx context.Context) {
	b := backoff.Backoff{Factor: 2, Min: time.Second, Max: time.Minute}
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := m.connect(ctx)
			if err == nil {
				return
			}
			d := b.Duration()
			klog.Warningf(
				"failed to establish connection with the .NET diagnostic socket pid=%d, next attempt in %s: %s",
				m.pid, d.String(), err,
			)
			time.Sleep(d)
		}
	}
}

func (m *DotNetMonitor) connect(ctx context.Context) error {
	nsPid, err := proc.GetNsPid(m.pid)
	if err != nil {
		return err
	}
	files, _ := filepath.Glob(proc.Path(m.pid, fmt.Sprintf("root/tmp/dotnet-diagnostic-%d-*-socket", nsPid)))

	if len(files) != 1 {
		return fmt.Errorf("no socket found")
	}
	klog.Infoln(".NET diagnostic socket:", files[0])
	c := dotnetdiag.NewClient(files[0], dotnetdiag.WithDialer(func(addr string) (net.Conn, error) {
		return net.DialTimeout("unix", addr, dotNetDiagnosticTimeout)
	}))

	if pi, err := c.ProcessInfo(); err == nil {
		m.info.WithLabelValues(pi.ClrProductVersion).Set(1)
	} else {
		m.info.WithLabelValues("unknown").Set(1)
	}

	ctc := dotnetdiag.CollectTracingConfig{
		CircularBufferSizeMB: 10,
		Providers: []dotnetdiag.ProviderConfig{
			{
				Keywords:     math.MaxInt64,
				LogLevel:     5,
				ProviderName: provider,
				FilterData:   "EventCounterIntervalSec=" + strconv.Itoa(int(dotNetEventInterval.Seconds())),
			},
		},
	}

	sess, err := c.CollectTracing(ctc)
	if err != nil {
		return err
	}
	defer func() {
		_ = sess.Close()
	}()

	stream := nettrace.NewStream(sess)
	if _, err = stream.Open(); err != nil {
		return err
	}

	metadata := map[int32]*nettrace.Metadata{}

	stream.EventHandler = func(e *nettrace.Blob) error {
		md, ok := metadata[e.Header.MetadataID]
		if !ok {
			return fmt.Errorf("metadata not found")
		}
		parser := nettrace.Parser{Buffer: e.Payload}

		if md.Header.ProviderName != provider {
			return nil
		}
		dnm := &dotNetMetric{
			fields: map[string]string{},
			values: map[string]float64{},
		}
		if err := parseFields(md.Payload.Fields, parser, dnm); err != nil {
			return err
		}

		m.processMetric(dnm.name(), dnm.units(), dnm.value())
		return nil
	}
	stream.MetadataHandler = func(md *nettrace.Metadata) error {
		metadata[md.Header.MetaDataID] = md
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if err = stream.Next(); err != nil {
				return err
			}
		}
	}
}

func parseFields(fields []nettrace.MetadataField, parser nettrace.Parser, metric *dotNetMetric) error {
	for _, field := range fields {
		switch field.TypeCode {
		case typecode.Object:
			if err := parseFields(field.Payload.Fields, parser, metric); err != nil {
				return err
			}
		case typecode.String:
			v := parser.UTF16NTS()
			if err := parser.Err(); err != nil {
				return err
			}
			metric.fields[field.Name] = v
		case typecode.Double:
			var v float64
			parser.Read(&v)
			if err := parser.Err(); err != nil {
				return err
			}
			metric.values[field.Name] = v
		case typecode.Single:
			var v float32
			parser.Read(&v)
			if err := parser.Err(); err != nil {
				return err
			}
			metric.values[field.Name] = float64(v)
		case typecode.Int32:
			var v int32
			parser.Read(&v)
			if err := parser.Err(); err != nil {
				return err
			}
			metric.values[field.Name] = float64(v)
		default:
			return fmt.Errorf("unsupported field type: %d", field.TypeCode)
		}
	}
	return nil
}

func dotNetApp(cmdline []byte, pid uint32) (string, error) {
	if parts := bytes.Split(cmdline, []byte{0}); len(parts) >= 2 { // dotnet Accounting.dll
		if bytes.HasSuffix(parts[0], []byte("dotnet")) && bytes.HasSuffix(parts[1], []byte(".dll")) {
			return strings.TrimSuffix(string(parts[1]), ".dll"), nil
		}
	}
	file, err := elf.Open(proc.Path(pid, "exe"))
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	res, _ := file.DynString(elf.DT_RPATH)
	if len(res) == 0 {
		res, _ = file.DynString(elf.DT_RUNPATH)
	}
	if len(res) == 1 && res[0] == "$ORIGIN/netcoredeps" {
		firstArg := bytes.Split(cmdline, []byte{0})[0]
		parts := strings.Split(string(firstArg), "/")
		app := parts[len(parts)-1]
		return app, nil
	}
	return "", nil
}
