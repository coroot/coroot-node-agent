package containers

import (
	"bytes"
	"context"
	"os"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/jpillora/backoff"
	"github.com/mdlayher/taskstats"
)

type GpuUsage struct {
	GPU    float64
	Memory float64
}

func (gu *GpuUsage) Reset() {
	gu.Memory = 0
	gu.GPU = 0
}

type Process struct {
	Pid       uint32
	StartedAt time.Time

	Flags proc.Flags

	netNsId string

	ctx        context.Context
	cancelFunc context.CancelFunc

	tracer        *ebpftracer.Tracer
	dotNetMonitor *DotNetMonitor
	isGolangApp   bool
	isRustApp     bool

	uprobeKeys            []ebpftracer.UprobeKey
	uprobeKeysLock        sync.Mutex
	instrumentDone        chan struct{}
	closed                bool
	goTlsUprobesChecked   bool
	openSslUprobesChecked bool
	rustlsUprobesChecked  bool
	javaTlsUprobesChecked bool
	pythonGilChecked      bool
	nodejsChecked         bool
	nodejsPrevStats       *ebpftracer.NodejsStats
	pythonPrevStats       *ebpftracer.PythonStats

	gpuUsageSamples []gpu.ProcessUsageSample
}

func NewProcess(pid uint32, stats *taskstats.Stats, tracer *ebpftracer.Tracer) *Process {
	p := &Process{Pid: pid, StartedAt: stats.BeginTime, tracer: tracer, instrumentDone: make(chan struct{})}
	p.Flags, _ = proc.GetFlags(pid)
	p.ctx, p.cancelFunc = context.WithCancel(context.Background())
	go p.instrument(tracer)
	return p
}

func (p *Process) NetNsId() string {
	if p.netNsId == "" {
		ns, err := proc.GetNetNs(p.Pid)
		if err != nil {
			return ""
		}
		p.netNsId = ns.UniqueId()
		_ = ns.Close()
	}
	return p.netNsId
}

func (p *Process) isHostNs() bool {
	return p.NetNsId() == hostNetNsId
}

func (p *Process) instrument(tracer *ebpftracer.Tracer) {
	defer close(p.instrumentDone)
	if delay := *flags.InstrumentationDelay; delay > 0 && !p.StartedAt.IsZero() {
		if wait := delay - time.Since(p.StartedAt); wait > 0 {
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}
	b := backoff.Backoff{Factor: 2, Min: time.Second, Max: time.Minute}
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			dest, err := os.Readlink(proc.Path(p.Pid, "exe"))
			if err != nil {
				return
			}
			cmdline := proc.GetCmdline(p.Pid)
			if dest != "/" && len(cmdline) > 0 {
				p.instrumentPython(cmdline, tracer)
				p.instrumentNodejs(dest, tracer)
				if dotNetAppName, err := dotNetApp(cmdline, p.Pid); err == nil {
					if dotNetAppName != "" {
						p.dotNetMonitor = NewDotNetMonitor(p.ctx, p.Pid, dotNetAppName)
					}
				}
				return
			}
			time.Sleep(b.Duration())
		}
	}
}

func (p *Process) instrumentPython(cmdline []byte, tracer *ebpftracer.Tracer) {
	if p.pythonGilChecked {
		return
	}
	p.pythonGilChecked = true
	parts := bytes.Split(cmdline, []byte{0})
	cmd := parts[0]
	if len(cmd) == 0 {
		return
	}
	cmdFields := bytes.Fields(cmd)
	if len(cmdFields) == 0 {
		return
	}
	cmd = bytes.TrimSuffix(cmdFields[0], []byte{':'})
	if !pythonCmd.Match(cmd) {
		return
	}
	if key := tracer.AttachPythonThreadLockProbes(p.Pid); key != nil {
		p.pythonPrevStats = &ebpftracer.PythonStats{}
		p.addUprobeKey(*key)
	}
}

func (p *Process) instrumentNodejs(exe string, tracer *ebpftracer.Tracer) {
	if p.nodejsChecked {
		return
	}
	p.nodejsChecked = true
	if !nodejsCmd.MatchString(exe) {
		return
	}
	if key := tracer.AttachNodejsProbes(p.Pid, exe); key != nil {
		p.nodejsPrevStats = &ebpftracer.NodejsStats{}
		p.addUprobeKey(*key)
	}
}

func (p *Process) addGpuUsageSample(sample gpu.ProcessUsageSample) {
	p.removeOldGpuUsageSamples(sample.Timestamp.Add(-gpuStatsWindow))
	p.gpuUsageSamples = append(p.gpuUsageSamples, sample)
}

func (p *Process) getGPUUsage() map[string]*GpuUsage {
	p.removeOldGpuUsageSamples(time.Now().Add(-gpuStatsWindow))
	if len(p.gpuUsageSamples) == 0 {
		return nil
	}
	gpuStatsWindowSeconds := gpuStatsWindow.Seconds()
	res := make(map[string]*GpuUsage)
	for _, sample := range p.gpuUsageSamples {
		u := res[sample.UUID]
		if u == nil {
			u = &GpuUsage{}
			res[sample.UUID] = u
		}
		u.GPU += float64(sample.GPUPercent) / gpuStatsWindowSeconds
		u.Memory += float64(sample.MemoryPercent) / gpuStatsWindowSeconds
	}
	return res
}

func (p *Process) removeOldGpuUsageSamples(cutoff time.Time) {
	i := 0
	for ; i < len(p.gpuUsageSamples); i++ {
		if p.gpuUsageSamples[i].Timestamp.After(cutoff) {
			break
		}
	}
	if i > 0 {
		copy(p.gpuUsageSamples, p.gpuUsageSamples[i:])
		p.gpuUsageSamples = p.gpuUsageSamples[:len(p.gpuUsageSamples)-i]
	}
}

func (p *Process) addUprobeKey(key ebpftracer.UprobeKey) {
	p.uprobeKeysLock.Lock()
	if p.closed {
		p.uprobeKeysLock.Unlock()
		p.tracer.ReleaseGlobalUprobes(key)
		return
	}
	p.uprobeKeys = append(p.uprobeKeys, key)
	p.uprobeKeysLock.Unlock()
}

func (p *Process) Close() {
	p.cancelFunc()
	<-p.instrumentDone
	p.uprobeKeysLock.Lock()
	p.closed = true
	keys := p.uprobeKeys
	p.uprobeKeys = nil
	p.uprobeKeysLock.Unlock()
	if len(keys) > 0 {
		p.tracer.ReleaseGlobalUprobes(keys...)
	}
}
