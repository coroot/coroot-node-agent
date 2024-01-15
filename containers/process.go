package containers

import (
	"context"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/mdlayher/taskstats"
)

type Process struct {
	Pid       uint32
	StartedAt time.Time
	NetNsId   string

	ctx        context.Context
	cancelFunc context.CancelFunc

	dotNetMonitor *DotNetMonitor

	uprobes               []link.Link
	goTlsUprobesChecked   bool
	openSslUprobesChecked bool
}

func NewProcess(pid uint32, stats *taskstats.Stats) *Process {
	ns, err := proc.GetNetNs(pid)
	if err != nil {
		return nil
	}
	defer ns.Close()
	p := &Process{Pid: pid, StartedAt: stats.BeginTime, NetNsId: ns.UniqueId()}
	p.ctx, p.cancelFunc = context.WithCancel(context.Background())
	p.instrument()
	return p
}

func (p *Process) isHostNs() bool {
	return p.NetNsId == hostNetNsId
}

func (p *Process) instrument() {
	if dotNetAppName, err := dotNetApp(p.Pid); err == nil {
		if dotNetAppName != "" {
			p.dotNetMonitor = NewDotNetMonitor(p.ctx, p.Pid, dotNetAppName)
		}
		return
	}
}

func (p *Process) Close() {
	p.cancelFunc()
	for _, u := range p.uprobes {
		_ = u.Close()
	}
}
