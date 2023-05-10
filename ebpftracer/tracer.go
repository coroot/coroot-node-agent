package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	"time"
)

const PayloadSize = 512

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
	EventTypeL7Request       EventType = 10

	EventReasonNone    EventReason = 0
	EventReasonOOMKill EventReason = 1
)

type L7Protocol uint8

const (
	L7ProtocolHTTP      L7Protocol = 1
	L7ProtocolPostgres  L7Protocol = 2
	L7ProtocolRedis     L7Protocol = 3
	L7ProtocolMemcached L7Protocol = 4
	L7ProtocolMysql     L7Protocol = 5
	L7ProtocolMongo     L7Protocol = 6
	L7ProtocolKafka     L7Protocol = 7
	L7ProtocolCassandra L7Protocol = 8
	L7ProtocolRabbitmq  L7Protocol = 9
)

func (p L7Protocol) String() string {
	switch p {
	case L7ProtocolHTTP:
		return "HTTP"
	case L7ProtocolPostgres:
		return "Postgres"
	case L7ProtocolRedis:
		return "Redis"
	case L7ProtocolMemcached:
		return "Memcached"
	case L7ProtocolMysql:
		return "Mysql"
	case L7ProtocolMongo:
		return "Mongo"
	case L7ProtocolKafka:
		return "Kafka"
	case L7ProtocolCassandra:
		return "Cassandra"
	}
	return "UNKNOWN:" + strconv.Itoa(int(p))
}

type L7Method uint8

const (
	L7MethodUnknown          L7Method = 0
	L7MethodProduce          L7Method = 1
	L7MethodConsume          L7Method = 2
	L7MethodStatementPrepare L7Method = 3
	L7MethodStatementClose   L7Method = 4
)

func (m L7Method) String() string {
	switch m {
	case L7MethodUnknown:
		return "unknown"
	case L7MethodProduce:
		return "produce"
	case L7MethodConsume:
		return "consume"
	}
	return "UNKNOWN:" + strconv.Itoa(int(m))
}

type L7Request struct {
	Protocol    L7Protocol
	Status      int
	Duration    time.Duration
	Method      L7Method
	StatementId uint32
	Payload     [PayloadSize]byte
}

func (r *L7Request) StatusString() string {
	switch r.Protocol {
	case L7ProtocolHTTP:
		return strconv.Itoa(r.Status)
	case L7ProtocolMongo, L7ProtocolKafka, L7ProtocolRabbitmq:
		return "unknown"
	}
	if r.Status == 500 {
		return "failed"
	}
	return "ok"
}

type Event struct {
	Type      EventType
	Reason    EventReason
	Pid       uint32
	SrcAddr   netaddr.IPPort
	DstAddr   netaddr.IPPort
	Fd        uint64
	Timestamp uint64
	L7Request *L7Request
}

type Tracer struct {
	collection *ebpf.Collection
	readers    map[string]*perf.Reader
	links      []link.Link
}

func NewTracer(events chan<- Event, kernelVersion string, disableL7Tracing bool) (*Tracer, error) {
	t := &Tracer{readers: map[string]*perf.Reader{}}
	if err := t.ebpf(events, kernelVersion, disableL7Tracing); err != nil {
		return nil, err
	}
	if disableL7Tracing {
		klog.Infoln("L7 tracing is disabled")
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
			Fd:      s.fd,
			SrcAddr: s.SAddr,
			DstAddr: s.DAddr,
		}
	}
	return nil
}

type perfMap struct {
	name                  string
	perCPUBufferSizePages int
	event                 rawEvent
}

func (t *Tracer) ebpf(ch chan<- Event, kernelVersion string, disableL7Tracing bool) error {
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

	perfMaps := []perfMap{
		{name: "proc_events", event: &procEvent{}, perCPUBufferSizePages: 4},
		{name: "tcp_listen_events", event: &tcpEvent{}, perCPUBufferSizePages: 4},
		{name: "tcp_connect_events", event: &tcpEvent{}, perCPUBufferSizePages: 8},
		{name: "tcp_retransmit_events", event: &tcpEvent{}, perCPUBufferSizePages: 4},
		{name: "file_events", event: &fileEvent{}, perCPUBufferSizePages: 4},
	}

	if !disableL7Tracing {
		perfMaps = append(perfMaps, perfMap{name: "l7_events", event: &l7Event{}, perCPUBufferSizePages: 16})
	}

	for _, pm := range perfMaps {
		r, err := perf.NewReader(t.collection.Maps[pm.name], pm.perCPUBufferSizePages*os.Getpagesize())
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to create ebpf reader: %w", err)
		}
		t.readers[pm.name] = r
		go runEventsReader(pm.name, r, ch, pm.event)
	}

	for name, spec := range spec.Programs {
		p := t.collection.Programs[name]
		if runtime.GOARCH == "arm64" && (spec.Name == "sys_enter_open" || spec.Name == "sys_exit_open") {
			continue
		}
		if disableL7Tracing {
			switch spec.Name {
			case "sys_enter_writev", "sys_enter_write", "sys_enter_sendto":
				continue
			case "sys_enter_read", "sys_enter_readv", "sys_enter_recvfrom":
				continue
			case "sys_exit_read", "sys_exit_readv", "sys_exit_recvfrom":
				continue
			}
		}
		var err error
		var l link.Link
		switch spec.Type {
		case ebpf.TracePoint:
			parts := strings.SplitN(spec.AttachTo, "/", 2)
			l, err = link.Tracepoint(parts[0], parts[1], p, nil)
		case ebpf.Kprobe:
			l, err = link.Kprobe(spec.AttachTo, p, nil)
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
	case EventTypeL7Request:
		return "l7-request"
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
	Fd        uint64
	Timestamp uint64
	Type      uint32
	Pid       uint32
	SPort     uint16
	DPort     uint16
	SAddr     [16]byte
	DAddr     [16]byte
}

func (e tcpEvent) Event() Event {
	return Event{
		Type:      EventType(e.Type),
		Pid:       e.Pid,
		SrcAddr:   ipPort(e.SAddr, e.SPort),
		DstAddr:   ipPort(e.DAddr, e.DPort),
		Fd:        e.Fd,
		Timestamp: e.Timestamp,
	}
}

type fileEvent struct {
	Type uint32
	Pid  uint32
	Fd   uint64
}

func (e fileEvent) Event() Event {
	return Event{Type: EventType(e.Type), Pid: e.Pid, Fd: e.Fd}
}

type l7Event struct {
	Fd                  uint64
	ConnectionTimestamp uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	StatementId         uint32
	Payload             [PayloadSize]byte
}

func (e l7Event) Event() Event {
	return Event{Type: EventTypeL7Request, Pid: e.Pid, Fd: e.Fd, Timestamp: e.ConnectionTimestamp, L7Request: &L7Request{
		Protocol:    L7Protocol(e.Protocol),
		Status:      int(e.Status),
		Duration:    time.Duration(e.Duration),
		Method:      L7Method(e.Method),
		StatementId: e.StatementId,
		Payload:     e.Payload,
	}}
}

func runEventsReader(name string, r *perf.Reader, ch chan<- Event, e rawEvent) {
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
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
