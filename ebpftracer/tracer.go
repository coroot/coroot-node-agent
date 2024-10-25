package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/proc"
	"golang.org/x/mod/semver"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const MaxPayloadSize = 1024 // 最大负载长度。比如 'http-length'。

type EventType int32 // .c uses default int32
type EventReason int32

// To be synchronized with ebpf.c definitions.
const (
	EventTypeUnknown          EventType = 0
	EventTypeProcessStart     EventType = 1
	EventTypeProcessExit      EventType = 2
	EventTypeConnectionOpen   EventType = 3
	EventTypeConnectionClose  EventType = 4
	EventTypeConnectionError  EventType = 5
	EventTypeListenOpen       EventType = 6
	EventTypeListenClose      EventType = 7
	EventTypeFileOpen         EventType = 8
	EventTypeTCPRetransmit    EventType = 9
	EventTypeL7Request        EventType = 10
	EventTypePythonThreadLock EventType = 11

	EventReasonUnknown EventReason = 0
	EventReasonOOMKill EventReason = 1
)

type TrafficStats struct {
	BytesSent     uint64
	BytesReceived uint64
}

// Event 类似 Flow，是建立 Span 的原始数据。
type Event struct {
	Type         EventType
	Reason       EventReason
	Pid          uint32
	TgidReqCs    uint64 // tgid of request from client-side
	TgidReqSs    uint64 // tgid of request from server-side
	TgidRespSs   uint64 // tgid of response from client-side
	TgidRespCs   uint64 // tgid of response from server-side
	SrcAddr      netaddr.IPPort
	DstAddr      netaddr.IPPort
	Fd           uint64
	Timestamp    uint64 // timestamp in nanoseconds
	Duration     time.Duration
	L7Request    *l7.Request
	TrafficStats *TrafficStats
}

type perfMapType uint8

const (
	perfMapTypeProcEvents         perfMapType = 1
	perfMapTypeTCPEvents          perfMapType = 2
	perfMapTypeFileEvents         perfMapType = 3
	perfMapTypeL7Events           perfMapType = 4
	perfMapTypePythonThreadEvents perfMapType = 5
)

type Tracer struct {
	kernelVersion    string
	disableL7Tracing bool

	collection *ebpf.Collection
	readers    map[string]*perf.Reader
	links      []link.Link
	uprobes    map[string]*ebpf.Program
}

func NewTracer(kernelVersion string, disableL7Tracing bool) *Tracer {
	if disableL7Tracing {
		klog.Infoln("L7 tracing is disabled")
	}
	return &Tracer{
		kernelVersion:    kernelVersion,
		disableL7Tracing: disableL7Tracing,

		readers: map[string]*perf.Reader{},
		uprobes: map[string]*ebpf.Program{},
	}
}

func (t *Tracer) Run(events chan<- Event) error {
	if err := t.ebpf(events); err != nil {
		return err
	}
	if err := t.init(events); err != nil {
		return err
	}
	return nil
}

func (t *Tracer) Close() {
	for _, p := range t.uprobes {
		_ = p.Close()
	}
	for _, l := range t.links {
		_ = l.Close()
	}
	for _, r := range t.readers {
		_ = r.Close()
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

	ebpfConnectionsMap := t.collection.Maps["active_connections"]
	timestamp := uint64(time.Now().UnixNano())
	for _, s := range sockets {
		typ := EventTypeConnectionOpen
		if s.Listen {
			typ = EventTypeListenOpen
		} else if listens[uint64(s.pid)<<32|uint64(s.SAddr.Port())] || s.DAddr.Port() > s.SAddr.Port() { // inbound
			continue
		}
		ch <- Event{
			Type:      typ,
			Pid:       s.pid,
			Timestamp: timestamp,
			Fd:        s.fd,
			SrcAddr:   s.SAddr,
			DstAddr:   s.DAddr,
		}
		if typ == EventTypeConnectionOpen {
			id := ConnectionId{FD: s.fd, PID: s.pid}
			conn := Connection{Timestamp: timestamp}
			if err := ebpfConnectionsMap.Update(id, conn, ebpf.UpdateNoExist); err != nil {
				klog.Warningln(err)
			}
		}
	}
	return nil
}

func (t *Tracer) ActiveConnectionsIterator() *ebpf.MapIterator {
	return t.collection.Maps["active_connections"].Iterate()
}

type ConnectionId struct {
	FD  uint64
	PID uint32
	_   uint32
}

type Connection struct {
	Timestamp     uint64
	BytesSent     uint64
	BytesReceived uint64
}

type perfMap struct {
	name                  string
	perCPUBufferSizePages int
	typ                   perfMapType
}

func (t *Tracer) ebpf(ch chan<- Event) error {
	if _, ok := ebpfProg[runtime.GOARCH]; !ok {
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
	kv := "v" + common.KernelMajorMinor(t.kernelVersion)
	var prg []byte
	for _, p := range ebpfProg[runtime.GOARCH] {
		if semver.Compare(kv, p.v) >= 0 {
			prg = p.p
			break
		}
	}
	if len(prg) == 0 {
		return fmt.Errorf("unsupported kernel version: %s", t.kernelVersion)
	}
	_, debugFsErr := os.Stat("/sys/kernel/debug/tracing")
	_, traceFsErr := os.Stat("/sys/kernel/tracing")

	if debugFsErr != nil && traceFsErr != nil {
		return fmt.Errorf("kernel tracing is not available: debugfs or tracefs must be mounted")
	}

	collectionSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prg))
	if err != nil {
		return fmt.Errorf("failed to load collection spec: %w", err)
	}
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	c, err := ebpf.NewCollectionWithOptions(collectionSpec, ebpf.CollectionOptions{
		//Programs: ebpf.ProgramOptions{LogLevel: 2, LogSize: 20 * 1024 * 1024},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			klog.Errorf("%+v", verr)
		}
		return fmt.Errorf("failed to load collection: %w", err)
	}
	t.collection = c

	perfMaps := []perfMap{
		{name: "proc_events", typ: perfMapTypeProcEvents, perCPUBufferSizePages: 4},
		{name: "tcp_listen_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "tcp_connect_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 8},
		{name: "tcp_retransmit_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "file_events", typ: perfMapTypeFileEvents, perCPUBufferSizePages: 4},
		{name: "python_thread_events", typ: perfMapTypePythonThreadEvents, perCPUBufferSizePages: 4},
	}

	if !t.disableL7Tracing {
		perfMaps = append(perfMaps, perfMap{name: "l7_events", typ: perfMapTypeL7Events, perCPUBufferSizePages: 32})
	}

	for _, pm := range perfMaps {
		r, err := perf.NewReader(t.collection.Maps[pm.name], pm.perCPUBufferSizePages*os.Getpagesize())
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to create ebpf reader: %w", err)
		}
		t.readers[pm.name] = r
		go runEventsReader(pm.name, r, ch, pm.typ)
	}

	for _, programSpec := range collectionSpec.Programs {
		program := t.collection.Programs[programSpec.Name]
		if t.disableL7Tracing {
			switch programSpec.Name {
			case "sys_enter_writev", "sys_enter_write", "sys_enter_sendto", "sys_enter_sendmsg", "sys_enter_sendmmsg":
				continue
			case "sys_enter_read", "sys_enter_readv", "sys_enter_recvfrom", "sys_enter_recvmsg":
				continue
			case "sys_exit_read", "sys_exit_readv", "sys_exit_recvfrom", "sys_exit_recvmsg":
				continue
			}
		}
		var l link.Link
		switch programSpec.Type {
		case ebpf.TracePoint:
			parts := strings.SplitN(programSpec.AttachTo, "/", 2)
			l, err = link.Tracepoint(parts[0], parts[1], program, nil)
		case ebpf.Kprobe:
			if strings.HasPrefix(programSpec.SectionName, "uprobe/") {
				t.uprobes[programSpec.Name] = program
				continue
			}
			l, err = link.Kprobe(programSpec.AttachTo, program, nil)
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
		return "tcp-connect-open"
	case EventTypeConnectionClose:
		return "tcp-connect-close"
	case EventTypeConnectionError:
		return "tcp-connect-error"
	case EventTypeListenOpen:
		return "tcp-listen-open"
	case EventTypeListenClose:
		return "tcp-listen-close"
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
	case EventReasonOOMKill:
		return "oom-kill"
	}
	return "unknown: " + strconv.Itoa(int(t))
}

type procEvent struct {
	Type   EventType
	Pid    uint32
	Reason uint32
}

// To be synchronized with `struct tcp_event`.
type tcpEvent struct {
	Fd            uint64
	Timestamp     uint64
	Duration      uint64
	Type          EventType
	Pid           uint32
	BytesSent     uint64
	BytesReceived uint64
	SPort         uint16
	DPort         uint16
	SAddr         [16]byte // supports IPv4 in IPv6
	DAddr         [16]byte
}

type fileEvent struct {
	Type EventType
	Pid  uint32
	Fd   uint64
}

// To be synchronized with `struct l7_event`.
type l7Event struct {
	Fd                  uint64
	ConnectionTimestamp uint64
	Pid                 uint32
	TgidReqCs           uint64
	TgidReqSs           uint64
	TgidRespSs          uint64
	TgidRespCs          uint64
	Status              uint32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	StatementId         uint32
	PayloadSize         uint64
}

type pythonThreadEvent struct {
	Type     EventType
	Pid      uint32
	Duration uint64
}

func runEventsReader(name string, r *perf.Reader, ch chan<- Event, typ perfMapType) {
	for {
		record, err := r.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				break
			}
			continue
		}
		if record.LostSamples > 0 {
			klog.Errorln(name, "lost samples:", record.LostSamples)
			continue
		}
		var event Event

		switch typ {
		case perfMapTypeL7Events:
			l7Event := &l7Event{}
			reader := bytes.NewBuffer(record.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, l7Event); err != nil {
				klog.Warningln("failed to read eBPF record: ", err)
				continue
			}
			payload := reader.Bytes()
			req := &l7.Request{
				Protocol: l7.Protocol(l7Event.Protocol),
				Status:   l7.Status(l7Event.Status),
				Duration: time.Duration(l7Event.Duration),
				Method:   l7.Method(l7Event.Method),
				ID:       l7Event.StatementId,
			}
			switch {
			case l7Event.PayloadSize == 0:
			case l7Event.PayloadSize > MaxPayloadSize:
				req.Payload = payload[:MaxPayloadSize]
			default:
				req.Payload = payload[:l7Event.PayloadSize]
			}
			event = Event{
				Type:       EventTypeL7Request,
				Pid:        l7Event.Pid,
				TgidReqCs:  l7Event.TgidReqCs,
				TgidReqSs:  l7Event.TgidReqSs,
				TgidRespSs: l7Event.TgidRespSs,
				TgidRespCs: l7Event.TgidRespCs,
				Fd:         l7Event.Fd,
				Timestamp:  l7Event.ConnectionTimestamp,
				L7Request:  req}
		case perfMapTypeFileEvents:
			v := &fileEvent{}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{Type: v.Type, Pid: v.Pid, Fd: v.Fd}
		case perfMapTypeProcEvents:
			v := &procEvent{}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{Type: v.Type, Reason: EventReason(v.Reason), Pid: v.Pid}
		case perfMapTypeTCPEvents:
			v := &tcpEvent{}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{
				Type:      v.Type,
				Pid:       v.Pid,
				SrcAddr:   ipPort(v.SAddr, v.SPort),
				DstAddr:   ipPort(v.DAddr, v.DPort),
				Fd:        v.Fd,
				Timestamp: v.Timestamp,
				Duration:  time.Duration(v.Duration),
			}
			if v.Type == EventTypeConnectionClose {
				event.TrafficStats = &TrafficStats{
					BytesSent:     v.BytesSent,
					BytesReceived: v.BytesReceived,
				}
			}
		case perfMapTypePythonThreadEvents:
			v := &pythonThreadEvent{}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{
				Type:     v.Type,
				Pid:      v.Pid,
				Duration: time.Duration(v.Duration),
			}
		default:
			continue
		}

		// 写入到 eBPF 消息队列
		ch <- event
	}
}

func ipPort(ip [16]byte, port uint16) netaddr.IPPort {
	i, _ := netaddr.FromStdIP(ip[:])
	return netaddr.IPPortFrom(i, port)
}
