package profiling

import (
	"bytes"
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
	pprofProfile "github.com/google/pprof/profile"
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
			TLSClientConfig: common.TlsConfig(),
		},
	}
	endpointUrl          *url.URL
	session              ebpfspy.Session
	targetFinder         = &TargetFinder{processes: map[uint32]*processInfo{}}
	jvmProfilingUpdateCh chan<- *containers.JvmProfilingUpdate
)

func Init(hostId, hostName string) (chan<- containers.ProcessInfo, chan *containers.JvmProfilingUpdate) {
	jvmUpdateCh := make(chan *containers.JvmProfilingUpdate, 100)
	jvmProfilingUpdateCh = jvmUpdateCh

	endpointUrl = *flags.ProfilesEndpoint
	if endpointUrl == nil {
		klog.Infoln("no profiles endpoint configured")
		return nil, jvmUpdateCh
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
		return nil, jvmUpdateCh
	}
	err = session.Start()
	if err != nil {
		klog.Errorln(err)
		session = nil
		return nil, jvmUpdateCh
	}
	go collect()

	processInfoCh := make(chan containers.ProcessInfo)
	targetFinder.start(processInfoCh)
	return processInfoCh, jvmUpdateCh
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

		if *flags.EnableJavaAsyncProfiler {
			collectAsyncProfilerProfiles()
		}
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

	b.Profile.SampleType[0].Type = "ebpf:cpu:nanoseconds"
	b.Profile.DurationNanos = CollectInterval.Nanoseconds()
	body := bytes.NewBuffer(nil)
	if _, err := b.Write(body); err != nil {
		return err
	}
	return post(u, q, body)
}

func collectAsyncProfilerProfiles() {
	targetFinder.lock.Lock()
	type jvmInfo struct {
		pid         uint32
		serviceName string
		containerID string
		started     bool
	}
	var jvms []jvmInfo
	for pid, pi := range targetFinder.processes {
		if pi.isJvm && !pi.asyncProfilerErr {
			jvms = append(jvms, jvmInfo{
				pid:         pid,
				serviceName: pi.serviceName,
				containerID: pi.containerId,
				started:     pi.asyncProfilerStarted,
			})
		}
	}
	targetFinder.lock.Unlock()

	for _, j := range jvms {
		if !j.started {
			if jvm.IsAsyncProfilerAlreadyLoaded(j.pid) {
				klog.Infof("pid=%d: async-profiler already loaded by another tool, skipping", j.pid)
				targetFinder.lock.Lock()
				if pi := targetFinder.processes[j.pid]; pi != nil {
					pi.asyncProfilerErr = true
				}
				targetFinder.lock.Unlock()
				continue
			}
			if err := jvm.DeployAndStartAsyncProfiler(j.pid); err != nil {
				klog.Warningf("async-profiler start pid=%d: %v", j.pid, err)
				targetFinder.lock.Lock()
				if pi := targetFinder.processes[j.pid]; pi != nil {
					pi.asyncProfilerErr = true
				}
				targetFinder.lock.Unlock()
			} else {
				targetFinder.lock.Lock()
				if pi := targetFinder.processes[j.pid]; pi != nil {
					pi.asyncProfilerStarted = true
				}
				targetFinder.lock.Unlock()
			}
			continue
		}

		data, err := jvm.CollectAsyncProfiler(j.pid)
		if err != nil {
			klog.Warningf("async-profiler collect pid=%d: %v", j.pid, err)
			continue
		}
		if data == nil {
			continue
		}
		profiles, err := jvm.ParseProfiles(data, CollectInterval)
		if err != nil {
			klog.Warningf("async-profiler parse pid=%d: %v", j.pid, err)
			continue
		}
		for _, jp := range profiles {
			if len(jp.Prof.Sample) == 0 {
				continue
			}
			if err := uploadProfile(jp.Prof, j.serviceName, j.containerID); err != nil {
				klog.Errorf("async-profiler upload pid=%d type=%s: %v", j.pid, jp.Type, err)
			}
			if jvmProfilingUpdateCh != nil {
				var total int64
				for _, s := range jp.Prof.Sample {
					total += s.Value[0]
				}
				u := &containers.JvmProfilingUpdate{Pid: j.pid}
				switch jp.Type {
				case jvm.ProfileTypeAllocSpace:
					u.AllocBytes = total
				case jvm.ProfileTypeAllocObjects:
					u.AllocObjects = total
				case jvm.ProfileTypeLockContentions:
					u.LockContentions = total
				case jvm.ProfileTypeLockDelay:
					u.LockTimeNs = total
				default:
					continue
				}
				jvmProfilingUpdateCh <- u
			}
		}
	}
}

func uploadProfile(prof *pprofProfile.Profile, serviceName, containerID string) error {
	u := *endpointUrl
	q := u.Query()
	q.Set("service.name", serviceName)
	q.Set("container.id", containerID)
	for _, l := range constLabels {
		q.Set(l.Name, l.Value)
	}

	body := bytes.NewBuffer(nil)
	if err := prof.Write(body); err != nil {
		return err
	}
	return post(u, q, body)
}

func post(u url.URL, q url.Values, body *bytes.Buffer) error {
	u.RawQuery = q.Encode()
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
		return fmt.Errorf("failed to upload profile %d: %s", resp.StatusCode, string(respBody))
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
			svc := common.ContainerIdToOtelServiceName(cid)
			tf.processes[pi.Pid] = &processInfo{
				startedAt: pi.StartedAt.UnixNano(),
				target: sd.NewTargetForTesting(cid, 0, sd.DiscoveryTarget{
					"service_name": svc,
				}),
				flags:       pi.Flags,
				serviceName: svc,
				containerId: cid,
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
		cmdline := proc.GetCmdline(pid)
		if proc.IsJvm(cmdline) {
			pi.isJvm = jvm.IsHotSpotJVM(pid)
			if !pi.flags.EbpfProfilingDisabled {
				pi.jvmPerfmapDumpSupported = jvm.IsPerfmapDumpSupported(cmdline)
			}
			klog.Infof("JVM detected PID: %d, hotspot: %t, perfmap: %t", pid, pi.isJvm, pi.jvmPerfmapDumpSupported)
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
	pi := tf.processes[pid]
	delete(tf.processes, pid)
	tf.lock.Unlock()
	if pi != nil && pi.asyncProfilerStarted {
		jvm.StopAsyncProfiler(pid)
	}
}

func (tf *TargetFinder) DebugInfo() []map[string]string {
	return nil
}

func (tf *TargetFinder) Update(_ sd.TargetsOptions) {
	tf.now = time.Now().UnixNano()
}

type processInfo struct {
	startedAt   int64
	target      *sd.Target
	serviceName string
	containerId string

	initialized bool
	flags       proc.Flags

	isJvm                   bool
	jvmPerfmapDumpSupported bool
	lastPerfmapDump         int64
	asyncProfilerStarted    bool
	asyncProfilerErr        bool
}
