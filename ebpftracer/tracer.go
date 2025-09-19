package ebpftracer

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
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
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const MaxPayloadSize = 1024

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

type TrafficStats struct {
	BytesSent     uint64
	BytesReceived uint64
}

type Event struct {
	Type          EventType
	Reason        EventReason
	Pid           uint32
	SrcAddr       netaddr.IPPort
	DstAddr       netaddr.IPPort
	ActualDstAddr netaddr.IPPort
	Fd            uint64
	Timestamp     uint64
	Duration      time.Duration
	L7Request     *l7.RequestData
	TrafficStats  *TrafficStats
	Mnt           uint64
	Log           bool
}

type perfMapType uint8

const (
	perfMapTypeProcEvents perfMapType = 1
	perfMapTypeTCPEvents  perfMapType = 2
	perfMapTypeFileEvents perfMapType = 3
	perfMapTypeL7Events   perfMapType = 4
)

type Tracer struct {
	disableL7Tracing bool
	hostNetNs        netns.NsHandle
	selfNetNs        netns.NsHandle

	collection *ebpf.Collection
	readers    map[string]*perf.Reader
	links      []link.Link
	uprobes    map[string]*ebpf.Program
}

func NewTracer(hostNetNs, selfNetNs netns.NsHandle, disableL7Tracing bool) *Tracer {
	if disableL7Tracing {
		klog.Infoln("L7 tracing is disabled")
	}
	return &Tracer{
		disableL7Tracing: disableL7Tracing,
		hostNetNs:        hostNetNs,
		selfNetNs:        selfNetNs,

		readers: map[string]*perf.Reader{},
		uprobes: map[string]*ebpf.Program{},
	}
}

func (t *Tracer) Run(events chan<- Event) error {
	if err := proc.ExecuteInNetNs(t.hostNetNs, t.selfNetNs, ensureConntrackEventsAreEnabled); err != nil {
		return err
	}
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

func (t *Tracer) ActiveConnectionsIterator() *ebpf.MapIterator {
	return t.collection.Maps["active_connections"].Iterate()
}

func (t *Tracer) NodejsStatsIterator() *ebpf.MapIterator {
	return t.collection.Maps["nodejs_stats"].Iterate()
}

func (t *Tracer) PythonStatsIterator() *ebpf.MapIterator {
	return t.collection.Maps["python_stats"].Iterate()
}

type NodejsStats struct {
	EventLoopBlockedTime time.Duration
}

type PythonStats struct {
	ThreadLockWaitTime time.Duration
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
	readTimeout           time.Duration
}

func (t *Tracer) ebpf(ch chan<- Event) error {
	if _, ok := ebpfProgs[runtime.GOARCH]; !ok {
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	var traceFsPath string
	for _, p := range []string{"/sys/kernel/debug/tracing", "/sys/kernel/tracing"} {
		if _, err := os.Stat(p); err == nil {
			traceFsPath = p
			break
		}
	}
	if traceFsPath == "" {
		return fmt.Errorf("kernel tracing is not available: debugfs or tracefs must be mounted")
	}

	var flags string
	if isCtxExtraPaddingRequired(traceFsPath) {
		flags = "ctx-extra-padding"
	}
	kv := common.GetKernelVersion()
	var prog []byte
	for _, p := range ebpfProgs[runtime.GOARCH] {
		pv, _ := common.VersionFromString(p.version)
		if !kv.GreaterOrEqual(pv) {
			continue
		}
		if flags != p.flags {
			continue
		}
		prog = p.prog
		break
	}
	if len(prog) == 0 {
		return fmt.Errorf("unsupported kernel version: %s %s", kv, flags)
	}

	reader, err := gzip.NewReader(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(prog)))
	if err != nil {
		return fmt.Errorf("invalid program encoding: %w", err)
	}
	prog, err = io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to ungzip program: %w", err)
	}
	collectionSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prog))
	if err != nil {
		return fmt.Errorf("failed to load collection spec: %w", err)
	}
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	c, err := ebpf.NewCollectionWithOptions(collectionSpec, ebpf.CollectionOptions{
		//Programs: ebpf.ProgramOptions{LogLevel: 2, LogSize: 20 * 1024 * 1024},
	})
	if err != nil {
		var vErr *ebpf.VerifierError
		if errors.As(err, &vErr) {
			klog.Errorf("%+v", vErr)
		}
		return fmt.Errorf("failed to load collection: %w", err)
	}
	t.collection = c

	perfMaps := []perfMap{
		{name: "proc_events", typ: perfMapTypeProcEvents, perCPUBufferSizePages: 4},
		{name: "tcp_listen_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "tcp_connect_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 8, readTimeout: 10 * time.Millisecond},
		{name: "tcp_retransmit_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "file_events", typ: perfMapTypeFileEvents, perCPUBufferSizePages: 4},
	}

	if !t.disableL7Tracing {
		perfMaps = append(perfMaps, perfMap{name: "l7_events", typ: perfMapTypeL7Events, perCPUBufferSizePages: 32})
	}

	pageSize := os.Getpagesize()
	for _, pm := range perfMaps {
		r, err := perf.NewReaderWithOptions(t.collection.Maps[pm.name], pm.perCPUBufferSizePages*pageSize, perf.ReaderOptions{WakeupEvents: 100})
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to create ebpf reader: %w", err)
		}
		t.readers[pm.name] = r
		go runEventsReader(pm.name, r, ch, pm.typ, pm.readTimeout)
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
			if err != nil && programSpec.SectionName == "kprobe/nf_ct_deliver_cached_events" {
				klog.Warningln("nf_conntrack may not be in use:", err)
				continue
			}
		}
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to link program '%s': %w", programSpec.Name, err)
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

type procEvent struct {
	Type   EventType
	Pid    uint32
	Reason uint32
}

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
	Aport         uint16
	SAddr         [16]byte
	DAddr         [16]byte
	AAddr         [16]byte
}

type fileEvent struct {
	Type EventType
	Pid  uint32
	Fd   uint64
	Mnt  uint64
	Log  uint64
}

type l7Event struct {
	Fd                  uint64
	ConnectionTimestamp uint64
	Pid                 uint32
	Status              int32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	StatementId         uint32
	PayloadSize         uint64
}

func runEventsReader(name string, r *perf.Reader, ch chan<- Event, typ perfMapType, readTimeout time.Duration) {
	if readTimeout == 0 {
		readTimeout = 100 * time.Millisecond
	}
	for {
		r.SetDeadline(time.Now().Add(readTimeout))
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
		var event Event

		switch typ {
		case perfMapTypeL7Events:
			v := &l7Event{}
			reader := bytes.NewBuffer(rec.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			payload := reader.Bytes()
			req := &l7.RequestData{
				Protocol:    l7.Protocol(v.Protocol),
				Status:      l7.Status(v.Status),
				Duration:    time.Duration(v.Duration),
				Method:      l7.Method(v.Method),
				StatementId: v.StatementId,
			}
			switch {
			case v.PayloadSize == 0:
			case v.PayloadSize > MaxPayloadSize:
				req.Payload = payload[:MaxPayloadSize]
			default:
				req.Payload = payload[:v.PayloadSize]
			}
			event = Event{Type: EventTypeL7Request, Pid: v.Pid, Fd: v.Fd, Timestamp: v.ConnectionTimestamp, L7Request: req}
		case perfMapTypeFileEvents:
			v := &fileEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{Type: v.Type, Pid: v.Pid, Fd: v.Fd, Mnt: v.Mnt, Log: v.Log > 0}
		case perfMapTypeProcEvents:
			v := &procEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{Type: v.Type, Reason: EventReason(v.Reason), Pid: v.Pid}
		case perfMapTypeTCPEvents:
			v := &tcpEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{
				Type:          v.Type,
				Pid:           v.Pid,
				SrcAddr:       ipPort(v.SAddr, v.SPort),
				DstAddr:       ipPort(v.DAddr, v.DPort),
				ActualDstAddr: ipPort(v.AAddr, v.Aport),
				Fd:            v.Fd,
				Timestamp:     v.Timestamp,
				Duration:      time.Duration(v.Duration),
			}
			if v.Type == EventTypeConnectionClose {
				event.TrafficStats = &TrafficStats{
					BytesSent:     v.BytesSent,
					BytesReceived: v.BytesReceived,
				}
			}
		default:
			continue
		}

		ch <- event
	}
}

func ipPort(ip [16]byte, port uint16) netaddr.IPPort {
	i, _ := netaddr.FromStdIP(ip[:])
	return netaddr.IPPortFrom(i, port)
}

func isCtxExtraPaddingRequired(traceFsPath string) bool {
	f, err := os.Open(path.Join(traceFsPath, "events/task/task_newtask/format"))
	if err != nil {
		klog.Errorln(err)
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		klog.Errorln(err)
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "common_preempt_lazy_count") {
			return true
		}
	}
	return false
}

const nfConntrackEventsParameterPath = "/proc/sys/net/netfilter/nf_conntrack_events"

func ensureConntrackEventsAreEnabled() error {
	v, err := common.ReadUintFromFile(nfConntrackEventsParameterPath)
	if err != nil {
		if common.IsNotExist(err) {
			klog.Warningf(
				"unable to check the value of %s, it appears that nf_conntrack is not loaded: %s",
				nfConntrackEventsParameterPath, err)
			return nil
		}
		return err
	}
	if v != 1 {
		klog.Infof("%s = %d, setting to 1", nfConntrackEventsParameterPath, v)
		if err = os.WriteFile(nfConntrackEventsParameterPath, []byte("1"), 0644); err != nil {
			return err
		}
	}
	return nil
}
