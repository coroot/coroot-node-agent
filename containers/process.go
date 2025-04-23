package containers

import (
	"bytes"
	"context"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/jpillora/backoff"
	"github.com/mdlayher/taskstats"
)

type Process struct {
	Pid       uint32
	StartedAt time.Time

	netNsId string

	ctx        context.Context
	cancelFunc context.CancelFunc

	dotNetMonitor *DotNetMonitor
	isGolangApp   bool

	uprobes               []link.Link
	goTlsUprobesChecked   bool
	openSslUprobesChecked bool
	pythonGilChecked      bool
}

func NewProcess(pid uint32, stats *taskstats.Stats, tracer *ebpftracer.Tracer) *Process {
	p := &Process{Pid: pid, StartedAt: stats.BeginTime}
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
	cmd = bytes.TrimSuffix(bytes.Fields(cmd)[0], []byte{':'})
	if !pythonCmd.Match(cmd) {
		return
	}
	p.uprobes = append(p.uprobes, tracer.AttachPythonThreadLockProbes(p.Pid)...)
}

func (p *Process) Close() {
	p.cancelFunc()
	for _, u := range p.uprobes {
		_ = u.Close()
	}
}
