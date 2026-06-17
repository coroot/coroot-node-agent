//go:build windows

package etwtracer

import (
	"context"
	"strconv"
	"sync"

	"github.com/0xrawsec/golang-etw/etw"
	"inet.af/netaddr"
)

const kernelNetworkProvider = "Microsoft-Windows-Kernel-Network:0xff::0x30"

type EventType uint16

const (
	EventTypeTCPDataSent EventType = iota + 1
	EventTypeTCPDataReceived
	EventTypeTCPConnectionAttempted
	EventTypeTCPDisconnect
	EventTypeTCPConnectionAccepted
	EventTypeTCPReconnectAttempted
)

type Event struct {
	Type   EventType
	Pid    uint32
	Src    netaddr.IPPort
	Dst    netaddr.IPPort
	Bytes  uint64
	ConnID string
}

type Tracer struct {
	ctx    context.Context
	cancel context.CancelFunc

	session  *etw.RealTimeSession
	consumer *etw.Consumer
	events   chan Event

	closeOnce sync.Once
}

func NewTracer() *Tracer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Tracer{
		ctx:    ctx,
		cancel: cancel,
		events: make(chan Event, 4096),
	}
}

func (t *Tracer) Events() <-chan Event {
	return t.events
}

func (t *Tracer) Start() error {
	provider, err := etw.ParseProvider(kernelNetworkProvider)
	if err != nil {
		return err
	}
	t.session = etw.NewRealTimeSession("CorootNodeAgentNetwork")
	if err := t.session.EnableProvider(provider); err != nil {
		return err
	}

	t.consumer = etw.NewRealTimeConsumer(t.ctx).FromSessions(t.session)
	t.consumer.EventCallback = func(e *etw.Event) error {
		event, ok := ParseKernelNetworkEvent(e)
		if !ok {
			return nil
		}
		select {
		case t.events <- event:
		case <-t.ctx.Done():
		}
		return nil
	}
	return t.consumer.Start()
}

func (t *Tracer) Close() {
	t.closeOnce.Do(func() {
		t.cancel()
		if t.consumer != nil {
			_ = t.consumer.Stop()
		}
		if t.session != nil {
			_ = t.session.Stop()
		}
		close(t.events)
	})
}

func ParseKernelNetworkEvent(e *etw.Event) (Event, bool) {
	if e == nil || e.System.Provider.Name != "Microsoft-Windows-Kernel-Network" {
		return Event{}, false
	}
	var typ EventType
	switch e.System.EventID {
	case 10, 26:
		typ = EventTypeTCPDataSent
	case 11, 27:
		typ = EventTypeTCPDataReceived
	case 12, 28:
		typ = EventTypeTCPConnectionAttempted
	case 13, 29:
		typ = EventTypeTCPDisconnect
	case 15, 31:
		typ = EventTypeTCPConnectionAccepted
	case 16, 32:
		typ = EventTypeTCPReconnectAttempted
	default:
		return Event{}, false
	}
	pid, ok := uint32Property(e, "PID")
	if !ok || pid == 0 {
		return Event{}, false
	}
	src, dst, ok := endpoints(e)
	if !ok {
		return Event{}, false
	}
	size, _ := uint64Property(e, "size")
	connID, _ := stringProperty(e, "connid")
	return Event{
		Type:   typ,
		Pid:    pid,
		Src:    src,
		Dst:    dst,
		Bytes:  size,
		ConnID: connID,
	}, true
}

func endpoints(e *etw.Event) (netaddr.IPPort, netaddr.IPPort, bool) {
	srcIP, ok := ipProperty(e, "saddr")
	if !ok {
		return netaddr.IPPort{}, netaddr.IPPort{}, false
	}
	dstIP, ok := ipProperty(e, "daddr")
	if !ok {
		return netaddr.IPPort{}, netaddr.IPPort{}, false
	}
	srcPort, ok := uint16Property(e, "sport")
	if !ok {
		return netaddr.IPPort{}, netaddr.IPPort{}, false
	}
	dstPort, ok := uint16Property(e, "dport")
	if !ok {
		return netaddr.IPPort{}, netaddr.IPPort{}, false
	}
	return netaddr.IPPortFrom(srcIP, srcPort), netaddr.IPPortFrom(dstIP, dstPort), true
}

func ipProperty(e *etw.Event, name string) (netaddr.IP, bool) {
	value, ok := stringProperty(e, name)
	if !ok || value == "" {
		return netaddr.IP{}, false
	}
	ip, err := netaddr.ParseIP(value)
	return ip, err == nil
}

func uint16Property(e *etw.Event, name string) (uint16, bool) {
	value, ok := uint64Property(e, name)
	if !ok || value > 0xffff {
		return 0, false
	}
	return uint16(value), true
}

func uint32Property(e *etw.Event, name string) (uint32, bool) {
	value, ok := uint64Property(e, name)
	if !ok || value > 0xffffffff {
		return 0, false
	}
	return uint32(value), true
}

func uint64Property(e *etw.Event, name string) (uint64, bool) {
	value, ok := stringProperty(e, name)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil
}

func stringProperty(e *etw.Event, name string) (string, bool) {
	value, ok := e.GetProperty(name)
	if !ok || value == nil {
		return "", false
	}
	switch v := value.(type) {
	case string:
		return v, true
	case uint16:
		return strconv.FormatUint(uint64(v), 10), true
	case uint32:
		return strconv.FormatUint(uint64(v), 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	case int:
		if v < 0 {
			return "", false
		}
		return strconv.FormatUint(uint64(v), 10), true
	default:
		return "", false
	}
}
