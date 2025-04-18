package profiling

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/containers"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/jvm"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/go-kit/log"
	ebpfspy "github.com/grafana/pyroscope/ebpf"
	"github.com/grafana/pyroscope/ebpf/cpp/demangle"
	"github.com/grafana/pyroscope/ebpf/metrics"
	"github.com/grafana/pyroscope/ebpf/pprof"
	"github.com/grafana/pyroscope/ebpf/sd"
	"github.com/grafana/pyroscope/ebpf/symtab"
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
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *flags.InsecureSkipVerify},
		},
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
		},
		SymbolOptions: symtab.SymbolOptions{
			GoTableFallback:    true,
			PythonFullFilePath: true,
			DemangleOptions:    demangle.DemangleFull,
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
	targetFinder.now = time.Now().UnixNano()
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
		bs := pprof.NewProfileBuilders(pprof.BuildersOptions{SampleRate: SampleRate, PerPIDProfile: false})
		if err := pprof.Collect(bs, session); err != nil {
			klog.Errorln(err)
		}
		klog.Infof("collected %d profiles in %s", len(bs.Builders), time.Since(t).Truncate(time.Millisecond))
		t = time.Now()
		var uploaded int
		for _, b := range bs.Builders {
			if err := upload(b); err != nil {
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
	for _, l := range b.Labels {
		switch l.Name {
		case "service_name":
			l.Name = "service.name"
		case "__container_id__":
			l.Name = "container.id"
		default:
			continue
		}
		q.Set(l.Name, l.Value)
	}
	for _, l := range constLabels {
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
	now       int64
}

func (tf *TargetFinder) start(processInfoCh <-chan containers.ProcessInfo) {
	go func() {
		for pi := range processInfoCh {
			tf.lock.Lock()
			cid := string(pi.ContainerId)
			tf.processes[pi.Pid] = &processInfo{
				startedAt: pi.StartedAt.UnixNano(),
				target: sd.NewTargetForTesting(cid, 0, sd.DiscoveryTarget{
					"service_name": common.ContainerIdToOtelServiceName(cid),
				}),
			}
			tf.lock.Unlock()
		}
	}()
}

func (tf *TargetFinder) FindTarget(pid uint32) *sd.Target {
	tf.lock.Lock()
	defer tf.lock.Unlock()
	pi := tf.processes[pid]
	if pi == nil {
		return nil
	}
	if tf.now-pi.startedAt < int64(CollectInterval) {
		return nil
	}
	var err error
	if !pi.initialized {
		pi.initialized = true
		if pi.flags, err = proc.GetFlags(pid); err != nil {
			delete(tf.processes, pid)
			return nil
		}
		if !pi.flags.EbpfProfilingDisabled {
			cmdline := proc.GetCmdline(pid)
			if proc.IsJvm(cmdline) {
				pi.jvmPerfmapDumpSupported = jvm.IsPerfmapDumpSupported(cmdline)
				klog.Infof("JVM detected PID: %d, perfmap dump supported: %t", pid, pi.jvmPerfmapDumpSupported)
			}
		}
	}
	if pi.flags.EbpfProfilingDisabled {
		return nil
	}
	if pi.jvmPerfmapDumpSupported && pi.lastPerfmapDump != tf.now {
		pi.lastPerfmapDump = tf.now
		if err = jvm.DumpPerfmap(pid); err != nil {
			klog.Warningln(err)
		}
	}
	return pi.target
}

func (tf *TargetFinder) RemoveDeadPID(pid uint32) {
	tf.lock.Lock()
	defer tf.lock.Unlock()
	delete(tf.processes, pid)
}

func (tf *TargetFinder) DebugInfo() []map[string]string {
	return nil
}

func (tf *TargetFinder) Update(_ sd.TargetsOptions) {
	tf.now = time.Now().UnixNano()
}

type processInfo struct {
	startedAt int64
	target    *sd.Target

	initialized bool
	flags       proc.Flags

	jvmPerfmapDumpSupported bool
	lastPerfmapDump         int64
}
