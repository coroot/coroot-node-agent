package profiling

import (
	"bytes"
	"fmt"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/containers"
	"github.com/go-kit/log"
	ebpfspy "github.com/grafana/pyroscope/ebpf"
	"github.com/grafana/pyroscope/ebpf/metrics"
	"github.com/grafana/pyroscope/ebpf/pprof"
	"github.com/grafana/pyroscope/ebpf/sd"
	"github.com/grafana/pyroscope/ebpf/symtab"
	"github.com/grafana/pyroscope/ebpf/symtab/elf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/labels"
	"hash/fnv"
	"io"
	"k8s.io/klog/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	CollectInterval = time.Minute
	SampleRate      = 100
	UploadTimeout   = 10 * time.Second
)

var (
	httpClient = http.Client{
		Timeout: UploadTimeout,
	}
	endpointUrl  *url.URL
	session      ebpfspy.Session
	targetFinder = &TargetFinder{
		processes: map[uint32]*processInfo{},
	}
)

func Init(processInfoCh <-chan containers.ProcessInfo) {
	endpoint := os.Getenv("PROFILES_ENDPOINT")
	if endpoint == "" {
		klog.Infoln("no profiles endpoint configured")
		return
	}
	klog.Infoln("profiles endpoint:", endpoint)

	var err error
	endpointUrl, err = url.Parse(endpoint)
	if err != nil {
		klog.Exitln(err)
	}

	reg := prometheus.NewRegistry()
	so := ebpfspy.SessionOptions{
		CollectUser:               true,
		CollectKernel:             true,
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
	session, err = ebpfspy.NewSession(log.NewNopLogger(), targetFinder, so)
	if err != nil {
		klog.Errorln(err)
		session = nil
		return
	}

	targetFinder.start(processInfoCh)
}

func Start() {
	if session == nil {
		return
	}
	targetFinder.now = time.Now()
	err := session.Start()
	if err != nil {
		klog.Errorln(err)
		session = nil
		return
	}
	go collect()
}

func Stop() {
	if session != nil {
		session.Stop()
	}
}

func collect() {
	ticker := time.NewTicker(CollectInterval)
	defer ticker.Stop()
	tPrev := time.Now()
	for range ticker.C {
		now := time.Now()
		targetFinder.now = now
		session.UpdateTargets(sd.TargetsOptions{})
		bs := pprof.NewProfileBuilders(SampleRate)
		err := session.CollectProfiles(func(target *sd.Target, stack []string, value uint64, pid uint32) {
			p := targetFinder.get(pid)
			if p == nil {
				return
			}
			b := bs.BuilderForTarget(p.hash, labels.Labels{{Value: p.labels}})
			b.AddSample(stack, value)
		})
		klog.Infof("collected %d profiles in %s", len(bs.Builders), time.Since(now).Truncate(time.Millisecond))
		if err != nil {
			klog.Errorln(err)
		}
		t := time.Now()
		var uploaded int
		for _, b := range bs.Builders {
			err = upload(b, tPrev, now)
			if err != nil {
				klog.Errorln(err)
				break
			}
			uploaded++
		}
		klog.Infof("uploaded %d profiles in %s", uploaded, time.Since(t).Truncate(time.Millisecond))
		tPrev = now
	}
}

func upload(b *pprof.ProfileBuilder, from, until time.Time) error {
	u := *endpointUrl
	q := u.Query()
	q.Set("name", "ebpf"+b.Labels[0].Value)
	q.Set("format", "pprof")
	q.Set("from", strconv.Itoa(int(from.Unix())))
	q.Set("until", strconv.Itoa(int(until.Unix())))
	q.Set("spyName", "coroot-node-agent")
	u.RawQuery = q.Encode()

	b.Profile.SampleType[0].Type = "samples"
	b.Profile.SampleType[0].Unit = "samples"
	for _, s := range b.Profile.Sample {
		s.Value[0] = s.Value[0] / b.Profile.Period
	}

	body := bytes.NewBuffer(nil)
	_, err := b.Write(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", u.String(), body)
	if err != nil {
		return err
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
}

type processInfo struct {
	containerId string
	startedAt   time.Time
	labels      string
	hash        uint64
}

func (pi *processInfo) calcHashAndLabels() {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(pi.containerId))
	pi.hash = hash.Sum64()
	var buf bytes.Buffer
	buf.WriteByte('{')
	buf.WriteString("container_id")
	buf.WriteByte('=')
	buf.WriteString(pi.containerId)
	buf.WriteByte(',')
	buf.WriteString("service_name")
	buf.WriteByte('=')
	buf.WriteString(common.ContainerIdToOtelServiceName(pi.containerId))
	buf.WriteByte('}')
	pi.labels = buf.String()
}
