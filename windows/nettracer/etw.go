//go:build windows

package nettracer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/coroot/coroot-node-agent/common"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	sessionName   = "CorootNetTrace"
	tcpipProvider = "Microsoft-Windows-TCPIP"
	dnsProvider   = "Microsoft-Windows-DNS-Client"

	kwConnectPath = 0x0000000400000000
	kwClosePath   = 0x0000001000000000
)

const (
	evtConnectCompleted = 1033 // TcpConnectTcbComplete: connect succeeded
	evtConnectFailure   = 1034 // TcpConnectTcbFailure: connect failed (refused/timeout/unreachable/...)
	evtDNSQueryStart    = 3006 // DNS-Client: query called (start, for latency)
	evtDNSQueryComplete = 3008 // DNS-Client: query completed (QueryName + QueryResults + QueryStatus)
)

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

const maxDNSPending = 10000

type NetworkEvent struct {
	PID            uint32
	RemoteAddrPort string
	Succeeded      bool
}

type DNSRequest struct {
	PID      uint32
	Type     string
	FQDN     string
	Status   string
	Duration time.Duration
}

type dnsPendKey struct {
	pid   uint32
	name  string
	qtype uint32
}

type ETWTracer struct {
	session      *etw.RealTimeSession
	consumer     *etw.Consumer
	cancel       context.CancelFunc
	onConnect    func(*NetworkEvent)
	onDNS        func(fqdn string, ips []netaddr.IP)
	onDNSRequest func(*DNSRequest)
	dnsPending   map[dnsPendKey]time.Time
}

func NewETWTracer(onConnect func(*NetworkEvent), onDNS func(string, []netaddr.IP), onDNSRequest func(*DNSRequest)) (*ETWTracer, error) {
	session := etw.NewRealTimeSession(sessionName)

	prov, err := etw.ParseProvider(tcpipProvider)
	if err != nil {
		return nil, err
	}
	prov.MatchAnyKeyword = kwConnectPath | kwClosePath
	if err := session.EnableProvider(prov); err != nil {
		session.Stop()
		return nil, err
	}

	if dp, err := etw.ParseProvider(dnsProvider); err != nil {
		klog.Warningf("failed to parse %s: %v", dnsProvider, err)
	} else if err := session.EnableProvider(dp); err != nil {
		klog.Warningf("failed to enable %s: %v", dnsProvider, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	consumer := etw.NewRealTimeConsumer(ctx).FromSessions(session)

	t := &ETWTracer{
		session: session, consumer: consumer, cancel: cancel,
		onConnect: onConnect, onDNS: onDNS, onDNSRequest: onDNSRequest,
		dnsPending: map[dnsPendKey]time.Time{},
	}

	if err := consumer.Start(); err != nil {
		cancel()
		session.Stop()
		return nil, err
	}
	go t.consume()

	klog.Infof("ETW session started: %s (providers=%s,%s)", sessionName, tcpipProvider, dnsProvider)
	return t, nil
}

func (t *ETWTracer) consume() {
	for e := range t.consumer.Events {
		t.handleEvent(e)
	}
}

func (t *ETWTracer) handleEvent(e *etw.Event) {
	switch e.System.EventID {
	case evtDNSQueryStart:
		t.recordDNSStart(e)
		return
	case evtDNSQueryComplete:
		t.handleDNS(e)
		return
	}

	var succeeded bool
	switch e.System.EventID {
	case evtConnectCompleted:
		succeeded = true
	case evtConnectFailure:
		succeeded = false
	default:
		return
	}

	pid, ok := propUint32(e, "ProcessId")
	if !ok || pid == 0 {
		return
	}
	remote, ok := remoteAddrPort(e, "RemoteAddress")
	if !ok {
		return
	}
	t.onConnect(&NetworkEvent{
		PID:            pid,
		RemoteAddrPort: remote,
		Succeeded:      succeeded,
	})
}

func (t *ETWTracer) recordDNSStart(e *etw.Event) {
	name, _ := e.GetPropertyString("QueryName")
	if name == "" {
		return
	}
	qtype, _ := propUint32(e, "QueryType")
	if len(t.dnsPending) >= maxDNSPending {
		t.dnsPending = map[dnsPendKey]time.Time{}
	}
	t.dnsPending[dnsPendKey{e.System.Execution.ProcessID, name, qtype}] = e.System.TimeCreated.SystemTime
}

func (t *ETWTracer) handleDNS(e *etw.Event) {
	name, _ := e.GetPropertyString("QueryName")
	if name == "" {
		return
	}
	qtype, _ := propUint32(e, "QueryType")
	ips := parseDNSResults(propString(e, "QueryResults"))
	typeStr := dnsTypeString(qtype)
	fqdn := common.NormalizeFQDN(name, typeStr)

	pid := e.System.Execution.ProcessID
	key := dnsPendKey{pid, name, qtype}
	var dur time.Duration
	if start, ok := t.dnsPending[key]; ok {
		dur = e.System.TimeCreated.SystemTime.Sub(start)
		delete(t.dnsPending, key)
	}

	if t.onDNS != nil && (qtype == dnsTypeA || qtype == dnsTypeAAAA) && len(ips) > 0 {
		t.onDNS(fqdn, ips)
	}

	if t.onDNSRequest == nil {
		return
	}
	status := dnsStatusString(propUint32OrZero(e, "QueryStatus"))
	if status == "" {
		return
	}
	if qtype == dnsTypeAAAA && status == "ok" && len(ips) == 0 {
		return
	}
	t.onDNSRequest(&DNSRequest{PID: pid, Type: typeStr, FQDN: fqdn, Status: status, Duration: dur})
}

func dnsTypeString(t uint32) string {
	switch t {
	case 1:
		return "TypeA"
	case 28:
		return "TypeAAAA"
	case 5:
		return "TypeCNAME"
	case 12:
		return "TypePTR"
	case 15:
		return "TypeMX"
	case 16:
		return "TypeTXT"
	case 33:
		return "TypeSRV"
	case 2:
		return "TypeNS"
	case 6:
		return "TypeSOA"
	case 255:
		return "TypeANY"
	default:
		return fmt.Sprintf("Type%d", t)
	}
}

func dnsStatusString(status uint32) string {
	switch status {
	case 0, 9501:
		return "ok"
	case 9001:
		return "format_error"
	case 9002:
		return "servfail"
	case 9003:
		return "nxdomain"
	case 9004:
		return "not_implemented"
	case 9005:
		return "refused"
	default:
		return ""
	}
}

func propString(e *etw.Event, name string) string {
	s, _ := e.GetPropertyString(name)
	return s
}

func propUint32OrZero(e *etw.Event, name string) uint32 {
	v, _ := propUint32(e, name)
	return v
}

func parseDNSResults(results string) []netaddr.IP {
	var ips []netaddr.IP
	for _, part := range strings.Split(results, ";") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "type:") {
			continue
		}
		if ip, err := netaddr.ParseIP(part); err == nil {
			ips = append(ips, ip.Unmap())
		}
	}
	return ips
}

func (t *ETWTracer) Stop() {
	t.consumer.Stop()
	t.cancel()
	t.session.Stop()
}

func propUint32(e *etw.Event, name string) (uint32, bool) {
	s, ok := e.GetPropertyString(name)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func remoteAddrPort(e *etw.Event, name string) (string, bool) {
	s, ok := e.GetPropertyString(name)
	if !ok || s == "" {
		return "", false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	return net.JoinHostPort(host, port), true
}
