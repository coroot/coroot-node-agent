package profiling

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/containers"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/go-kit/log"
	ebpfspy "github.com/grafana/pyroscope/ebpf"
	"github.com/grafana/pyroscope/ebpf/metrics"
	"github.com/grafana/pyroscope/ebpf/pprof"
	"github.com/grafana/pyroscope/ebpf/sd"
	"github.com/grafana/pyroscope/ebpf/symtab"
	"github.com/grafana/pyroscope/ebpf/symtab/elf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/labels"
	"k8s.io/klog/v2"
)

const (
	CollectInterval = time.Minute
	SampleRate      = 100
	UploadTimeout   = 10 * time.Second
)

var (
	constLabels labels.Labels
	httpClient  = http.Client{
		Timeout: UploadTimeout,
	}
	endpointUrl  *url.URL
	session      ebpfspy.Session
	targetFinder = &TargetFinder{
		processes: map[uint32]*processInfo{},
	}
)

func Init(hostId, hostName string) chan<- containers.ProcessInfo {
	endpointUrl = *flags.ProfilesEndpoint
	if endpointUrl == nil {
		klog.Infoln("no profiles endpoint configured")
		return nil
	}
	klog.Infoln("profiles endpoint:", endpointUrl.String())

	constLabels = labels.Labels{
		{Name: "host.name", Value: hostName},
		{Name: "host.id", Value: hostId},
	}

	reg := prometheus.NewRegistry()
	so := ebpfspy.SessionOptions{
		CollectUser:               true,
		CollectKernel:             false,
		UnknownSymbolModuleOffset: true,
		UnknownSymbolAddress:      false,
		PythonEnabled:             true,
		CacheOptions: symtab.CacheOptions{
			PidCacheOptions: symtab.GCacheOptions{
				Size:       256,
				KeepRounds: 8,
			},
			BuildIDCacheOptions: symtab.GCacheOptions{
				Size:       256,
				KeepRounds: 8,
			},
			SameFileCacheOptions: symtab.GCacheOptions{
				Size:       256,
				KeepRounds: 8,
			},
			SymbolOptions: symtab.SymbolOptions{
				GoTableFallback:    true,
				PythonFullFilePath: false,
				DemangleOptions:    elf.DemangleFull,
			},
		},
		Metrics: &metrics.Metrics{
			Symtab: metrics.NewSymtabMetrics(reg),
			Python: metrics.NewPythonMetrics(reg),
		},
		SampleRate: SampleRate,
	}
	var err error
	session, err = ebpfspy.NewSession(log.NewNopLogger(), targetFinder, so)
	if err != nil {
		klog.Errorln(err)
		session = nil
		return nil
	}
	err = session.Start()
	if err != nil {
		klog.Errorln(err)
		session = nil
		return nil
	}
	go collect()

	processInfoCh := make(chan containers.ProcessInfo)
	targetFinder.start(processInfoCh)
	return processInfoCh
}

func Start() {
	if session == nil {
		return
	}
	targetFinder.now = time.Now()
	session.UpdateTargets(sd.TargetsOptions{})
}

func Stop() {
	if session != nil {
		session.Stop()
	}
}

func collect() {
	ticker := time.NewTicker(CollectInterval)
	defer ticker.Stop()
	for t := range ticker.C {
		session.UpdateTargets(sd.TargetsOptions{})
		bs := pprof.NewProfileBuilders(SampleRate)
		err := session.CollectProfiles(func(target *sd.Target, stack []string, value uint64, pid uint32, aggregation ebpfspy.SampleAggregation) {
			pi := targetFinder.get(pid)
			if pi == nil {
				return
			}
			b := bs.BuilderForTarget(pi.hash, pi.labels)
			if aggregation == ebpfspy.SampleAggregated {
				b.CreateSample(stack, value)
			} else {
				b.CreateSampleOrAddValue(stack, value)
			}
		})
		klog.Infof("collected %d profiles in %s", len(bs.Builders), time.Since(t).Truncate(time.Millisecond))
		if err != nil {
			klog.Errorln(err)
		}
		t = time.Now()
		var uploaded int
		for _, b := range bs.Builders {
			err = upload(b)
			if err != nil {
				klog.Errorln(err)
				break
			}
			uploaded++
		}
		klog.Infof("uploaded %d profiles in %s", uploaded, time.Since(t).Truncate(time.Millisecond))
	}
}

func upload(b *pprof.ProfileBuilder) error {
	u := *endpointUrl
	q := u.Query()
	for _, l := range append(b.Labels, constLabels...) {
		q.Set(l.Name, l.Value)
	}
	u.RawQuery = q.Encode()

	b.Profile.SampleType[0].Type = "ebpf:cpu:nanoseconds"
	b.Profile.DurationNanos = CollectInterval.Nanoseconds()
	body := bytes.NewBuffer(nil)
	_, err := b.Write(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, u.String(), body)
	if err != nil {
		return err
	}
	for k, v := range common.AuthHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to upload %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

type TargetFinder struct {
	processes map[uint32]*processInfo
	lock      sync.Mutex
	now       time.Time
}

func (tf *TargetFinder) start(processInfoCh <-chan containers.ProcessInfo) {
	go func() {
		for pi := range processInfoCh {
			tf.lock.Lock()
			tf.processes[pi.Pid] = &processInfo{
				containerId: string(pi.ContainerId),
				startedAt:   pi.StartedAt,
			}
			tf.lock.Unlock()
		}
	}()
}

func (tf *TargetFinder) get(pid uint32) *processInfo {
	tf.lock.Lock()
	pi := tf.processes[pid]
	tf.lock.Unlock()
	if pi == nil {
		return nil
	}
	if tf.now.Sub(pi.startedAt) < CollectInterval {
		return nil
	}
	if pi.hash == 0 {
		pi.calcHashAndLabels()
	}
	return pi
}

func (tf *TargetFinder) FindTarget(pid uint32) *sd.Target {
	p := tf.get(pid)
	if p == nil {
		return nil
	}
	return &sd.Target{}
}

func (tf *TargetFinder) RemoveDeadPID(pid uint32) {
	tf.lock.Lock()
	defer tf.lock.Unlock()
	delete(tf.processes, pid)
}

func (tf *TargetFinder) DebugInfo() []string {
	return nil
}

func (tf *TargetFinder) Update(_ sd.TargetsOptions) {
	tf.now = time.Now()
}

type processInfo struct {
	containerId string
	startedAt   time.Time
	labels      labels.Labels
	hash        uint64
}

func (pi *processInfo) calcHashAndLabels() {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(pi.containerId))
	pi.hash = hash.Sum64()
	pi.labels = labels.Labels{
		{Name: "service.name", Value: common.ContainerIdToOtelServiceName(pi.containerId)},
		{Name: "container.id", Value: pi.containerId},
	}
}
