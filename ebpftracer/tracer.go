package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"golang.org/x/mod/semver"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type EventType uint32
type EventReason uint32

const (
	EventTypeProcessStart    EventType = 1
	EventTypeProcessExit     EventType = 2
	EventTypeConnectionOpen  EventType = 3
	EventTypeConnectionClose EventType = 4
	EventTypeConnectionError EventType = 5
	EventTypeListenOpen      EventType = 6
	EventTypeListenClose     EventType = 7
	EventTypeFileOpen        EventType = 8
	EventTypeTCPRetransmit   EventType = 9

	EventReasonNone    EventReason = 0
	EventReasonOOMKill EventReason = 1
)

type Event struct {
	Type    EventType
	Reason  EventReason
	Pid     uint32
	SrcAddr netaddr.IPPort
	DstAddr netaddr.IPPort
	Fd      uint32
}

type Tracer struct {
	collection *ebpf.Collection
	readers    map[string]*perf.Reader
	links      []link.Link
}

func NewTracer(events chan<- Event, kernelVersion string) (*Tracer, error) {
	t := &Tracer{readers: map[string]*perf.Reader{}}
	if err := t.ebpf(events, kernelVersion); err != nil {
		return nil, err
	}
	if err := t.init(events); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tracer) Close() {
	for _, l := range t.links {
		l.Close()
	}
	for _, r := range t.readers {
		r.Close()
	}
	t.collection.Close()
}

func (t *Tracer) init(ch chan<- Event) error {
	pids, err := proc.ListPids()
	if err != nil {
		return fmt.Errorf("failed to list pids: %w", err)
	}
	for _, pid := range pids {
		ch <- Event{Type: EventTypeProcessStart, Pid: pid}
	}

	fds, sockets := readFds(pids)
	for _, fd := range fds {
		ch <- Event{Type: EventTypeFileOpen, Pid: fd.pid, Fd: fd.fd}
	}

	listens := map[uint64]bool{}
	for _, s := range sockets {
		if s.Listen {
			listens[uint64(s.pid)<<32|uint64(s.SAddr.Port())] = true
		}
	}

	for _, s := range sockets {
		typ := EventTypeConnectionOpen
		if s.Listen {
			typ = EventTypeListenOpen
		} else if listens[uint64(s.pid)<<32|uint64(s.SAddr.Port())] || s.DAddr.Port() > s.SAddr.Port() { // inbound
			continue
		}
		ch <- Event{
			Type:    typ,
			Pid:     s.pid,
			SrcAddr: s.SAddr,
			DstAddr: s.DAddr,
		}
	}
	return nil
}

func (t *Tracer) ebpf(ch chan<- Event, kernelVersion string) error {
	kv := "v" + common.KernelMajorMinor(kernelVersion)
	var prg []byte
	for _, p := range ebpfProg {
		if semver.Compare(kv, p.v) >= 0 {
			prg = p.p
			break
		}
	}
	if len(prg) == 0 {
		return fmt.Errorf("unsupported kernel version: %s", kernelVersion)
	}

	if _, err := os.Stat("/sys/kernel/debug/tracing"); err != nil {
		return fmt.Errorf("kernel tracing is not available: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prg))
	if err != nil {
		return fmt.Errorf("failed to load spec: %w", err)
	}
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to load collection: %w", err)
	}
	t.collection = c

	events := map[string]rawEvent{
		"proc_events":           &procEvent{},
		"tcp_listen_events":     &tcpEvent{},
		"tcp_connect_events":    &tcpEvent{},
		"tcp_retransmit_events": &tcpEvent{},
		"file_events":           &fileEvent{},
	}
	for name, typ := range events {
		r, err := perf.NewReader(t.collection.Maps[name], os.Getpagesize())
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to create ebpf reader: %w", err)
		}
		t.readers[name] = r
		go runEventsReader(name, r, ch, typ)
	}

	for name, spec := range spec.Programs {
		p := t.collection.Programs[name]
		if runtime.GOARCH == "arm64" && (spec.Name == "sys_enter_open" || spec.Name == "sys_exit_open") {
			continue
		}
		var err error
		var l link.Link
		switch spec.Type {
		case ebpf.TracePoint:
			parts := strings.SplitN(spec.AttachTo, "/", 2)
			l, err = link.Tracepoint(parts[0], parts[1], p)
		case ebpf.Kprobe:
			l, err = link.Kprobe(spec.AttachTo, p)
		}
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to link program: %w", err)
		}
		t.links = append(t.links, l)
	}

	return nil
}

func (t EventType) String() string {
	switch t {
	case EventTypeProcessStart:
		return "process-start"
	case EventTypeProcessExit:
		return "process-exit"
	case EventTypeConnectionOpen:
		return "connection-open"
	case EventTypeConnectionClose:
		return "connection-close"
	case EventTypeConnectionError:
		return "connection-error"
	case EventTypeListenOpen:
		return "listen-open"
	case EventTypeListenClose:
		return "listen-close"
	case EventTypeFileOpen:
		return "file-open"
	case EventTypeTCPRetransmit:
		return "tcp-retransmit"
	}
	return "unknown: " + strconv.Itoa(int(t))
}

func (t EventReason) String() string {
	switch t {
	case EventReasonNone:
		return "none"
	case EventReasonOOMKill:
		return "oom-kill"
	}
	return "unknown: " + strconv.Itoa(int(t))
}

type rawEvent interface {
	Event() Event
}

type procEvent struct {
	Type   uint32
	Pid    uint32
	Reason uint32
}

func (e procEvent) Event() Event {
	return Event{Type: EventType(e.Type), Reason: EventReason(e.Reason), Pid: e.Pid}
}

type tcpEvent struct {
	Type  uint32
	Pid   uint32
	SPort uint16
	DPort uint16
	SAddr [16]byte
	DAddr [16]byte
}

func (e tcpEvent) Event() Event {
	return Event{Type: EventType(e.Type), Pid: e.Pid, SrcAddr: ipPort(e.SAddr, e.SPort), DstAddr: ipPort(e.DAddr, e.DPort)}
}

type fileEvent struct {
	Type uint32
	Pid  uint32
	Fd   uint32
}

func (e fileEvent) Event() Event {
	return Event{Type: EventType(e.Type), Pid: e.Pid, Fd: e.Fd}
}

func runEventsReader(name string, r *perf.Reader, ch chan<- Event, e rawEvent) {
	for {
		rec, err := r.Read()
		if err != nil {
			if perf.IsClosed(err) {
				break
			}
			continue
		}
		if rec.LostSamples > 0 {
			klog.Errorln(name, "lost samples:", rec.LostSamples)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, e); err != nil {
			klog.Warningln("failed to read msg:", err)
			continue
		}
		ch <- e.Event()
	}
}

func ipPort(ip [16]byte, port uint16) netaddr.IPPort {
	i, _ := netaddr.FromStdIP(ip[:])
	return netaddr.IPPortFrom(i, port)
}
