package containers

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/node"
	"github.com/coroot/coroot-node-agent/pinger"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/coroot/logparser"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netns"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

var (
	gcInterval  = 10 * time.Minute
	pingTimeout = 300 * time.Millisecond
)

type ContainerID string

type ContainerNetwork struct {
	NetworkID string
}

type ContainerMetadata struct {
	name        string
	labels      map[string]string
	volumes     map[string]string
	logPath     string
	image       string
	logDecoder  logparser.Decoder
	hostListens map[string][]netaddr.IPPort
	networks    map[string]ContainerNetwork
	env         map[string]string
}

type Delays struct {
	cpu  time.Duration
	disk time.Duration
}

type LogParser struct {
	parser *logparser.Parser
	stop   func()
}

func (p *LogParser) Stop() {
	if p.stop != nil {
		p.stop()
	}
	p.parser.Stop()
}

type AddrPair struct {
	src netaddr.IPPort
	dst netaddr.IPPort
}

type ActiveConnection struct {
	Dest       netaddr.IPPort
	ActualDest netaddr.IPPort
	Pid        uint32
	Fd         uint64
	Timestamp  uint64
	Closed     time.Time

	http2Parser    *l7.Http2Parser
	postgresParser *l7.PostgresParser
	mysqlParser    *l7.MysqlParser
}

type ListenDetails struct {
	ClosedAt time.Time
	NsIPs    []netaddr.IP
}

type PidFd struct {
	Pid uint32
	Fd  uint64
}

type Container struct {
	id       ContainerID
	cgroup   *cgroup.Cgroup
	metadata *ContainerMetadata

	processes map[uint32]*Process

	startedAt time.Time
	zombieAt  time.Time
	restarts  int

	delays      Delays
	delaysByPid map[uint32]Delays
	delaysLock  sync.Mutex

	listens map[netaddr.IPPort]map[uint32]*ListenDetails
	ipsByNs map[string][]netaddr.IP

	connectsSuccessful map[AddrPair]int64           // dst:actual_dst -> count
	connectsFailed     map[netaddr.IPPort]int64     // dst -> count
	connectLastAttempt map[netaddr.IPPort]time.Time // dst -> time
	connectionsActive  map[AddrPair]*ActiveConnection
	connectionsByPidFd map[PidFd]*ActiveConnection
	retransmits        map[AddrPair]int64 // dst:actual_dst -> count

	l7Stats  L7Stats
	dnsStats *L7Metrics

	oomKills int

	mounts map[string]proc.MountInfo

	logParsers map[string]*LogParser

	hostConntrack *Conntrack
	nsConntrack   *Conntrack
	lbConntracks  []*Conntrack

	lock sync.RWMutex

	done chan struct{}
}

func NewContainer(id ContainerID, cg *cgroup.Cgroup, md *ContainerMetadata, hostConntrack *Conntrack, pid uint32) (*Container, error) {
	netNs, err := proc.GetNetNs(pid)
	if err != nil {
		return nil, err
	}
	defer netNs.Close()
	c := &Container{
		id:       id,
		cgroup:   cg,
		metadata: md,

		processes: map[uint32]*Process{},

		delaysByPid: map[uint32]Delays{},

		listens: map[netaddr.IPPort]map[uint32]*ListenDetails{},
		ipsByNs: map[string][]netaddr.IP{},

		connectsSuccessful: map[AddrPair]int64{},
		connectsFailed:     map[netaddr.IPPort]int64{},
		connectLastAttempt: map[netaddr.IPPort]time.Time{},
		connectionsActive:  map[AddrPair]*ActiveConnection{},
		connectionsByPidFd: map[PidFd]*ActiveConnection{},
		retransmits:        map[AddrPair]int64{},
		l7Stats:            L7Stats{},
		dnsStats:           &L7Metrics{},

		mounts: map[string]proc.MountInfo{},

		logParsers: map[string]*LogParser{},

		hostConntrack: hostConntrack,

		done: make(chan struct{}),
	}

	for _, n := range md.networks {
		if nsHandle := FindNetworkLoadBalancerNs(n.NetworkID); nsHandle.IsOpen() {
			if ct, err := NewConntrack(nsHandle); err != nil {
				klog.Warningln(err)
			} else {
				c.lbConntracks = append(c.lbConntracks, ct)
			}
			_ = nsHandle.Close()
		}
	}

	c.runLogParser("")

	go func() {
		ticker := time.NewTicker(gcInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case t := <-ticker.C:
				c.gc(t)
			}
		}
	}()

	return c, nil
}

func (c *Container) Close() {
	for _, p := range c.logParsers {
		p.Stop()
	}
	for _, ct := range c.lbConntracks {
		_ = ct.Close()
	}
	if c.nsConntrack != nil {
		_ = c.nsConntrack.Close()
	}
	close(c.done)
}

func (c *Container) Dead(now time.Time) bool {
	return !c.zombieAt.IsZero() && now.Sub(c.zombieAt) > gcInterval
}

func (c *Container) Describe(ch chan<- *prometheus.Desc) {
	// some fixed metric description is required here to register/unregister the collector correctly
	ch <- prometheus.NewDesc("container", "", nil, nil)
}

func (c *Container) Collect(ch chan<- prometheus.Metric) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.metadata.image != "" {
		ch <- gauge(metrics.ContainerInfo, 1, c.metadata.image)
	}

	ch <- counter(metrics.Restarts, float64(c.restarts))

	if cpu, err := c.cgroup.CpuStat(); err == nil {
		if cpu.LimitCores > 0 {
			ch <- gauge(metrics.CPULimit, cpu.LimitCores)
		}
		ch <- counter(metrics.CPUUsage, cpu.UsageSeconds)
		ch <- counter(metrics.ThrottledTime, cpu.ThrottledTimeSeconds)
	}

	if taskstatsClient != nil {
		c.updateDelays()
		ch <- counter(metrics.CPUDelay, float64(c.delays.cpu)/float64(time.Second))
		ch <- counter(metrics.DiskDelay, float64(c.delays.disk)/float64(time.Second))
	}

	if s, err := c.cgroup.MemoryStat(); err == nil {
		ch <- gauge(metrics.MemoryRss, float64(s.RSS))
		ch <- gauge(metrics.MemoryCache, float64(s.Cache))
		if s.Limit > 0 {
			ch <- gauge(metrics.MemoryLimit, float64(s.Limit))
		}
	}

	if c.oomKills > 0 {
		ch <- counter(metrics.OOMKills, float64(c.oomKills))
	}

	if disks, err := node.GetDisks(); err == nil {
		ioStat, _ := c.cgroup.IOStat()
		for majorMinor, mounts := range c.getMounts() {
			dev := disks.GetParentBlockDevice(majorMinor)
			if dev == nil {
				continue
			}
			for mountPoint, fsStat := range mounts {
				dls := []string{mountPoint, dev.Name, c.metadata.volumes[mountPoint]}
				ch <- gauge(metrics.DiskSize, float64(fsStat.CapacityBytes), dls...)
				ch <- gauge(metrics.DiskUsed, float64(fsStat.UsedBytes), dls...)
				ch <- gauge(metrics.DiskReserved, float64(fsStat.ReservedBytes), dls...)
				if io, ok := ioStat[majorMinor]; ok {
					ch <- counter(metrics.DiskReadOps, float64(io.ReadOps), dls...)
					ch <- counter(metrics.DiskReadBytes, float64(io.ReadBytes), dls...)
					ch <- counter(metrics.DiskWriteOps, float64(io.WriteOps), dls...)
					ch <- counter(metrics.DiskWriteBytes, float64(io.WrittenBytes), dls...)
				}
			}
		}
	}

	for addr, open := range c.getListens() {
		ch <- gauge(metrics.NetListenInfo, float64(open), addr.String(), "")
	}
	for proxy, addrs := range c.getProxiedListens() {
		for addr := range addrs {
			ch <- gauge(metrics.NetListenInfo, 1, addr.String(), proxy)
		}
	}

	for d, count := range c.connectsSuccessful {
		ch <- counter(metrics.NetConnectsSuccessful, float64(count), d.src.String(), d.dst.String())
	}
	for dst, count := range c.connectsFailed {
		ch <- counter(metrics.NetConnectsFailed, float64(count), dst.String())
	}
	for d, count := range c.retransmits {
		ch <- counter(metrics.NetRetransmits, float64(count), d.src.String(), d.dst.String())
	}

	connections := map[AddrPair]int{}
	for addrPair, conn := range c.connectionsActive {
		if !conn.Closed.IsZero() {
			continue
		}
		connections[AddrPair{src: addrPair.dst, dst: conn.ActualDest}]++
	}
	for d, count := range connections {
		ch <- gauge(metrics.NetConnectionsActive, float64(count), d.src.String(), d.dst.String())
	}

	for source, p := range c.logParsers {
		for _, c := range p.parser.GetCounters() {
			ch <- counter(metrics.LogMessages, float64(c.Messages), source, c.Level.String(), c.Hash, c.Sample)
		}
	}

	appTypes := map[string]struct{}{}
	seenJvms := map[string]bool{}
	for pid, process := range c.processes {
		cmdline := proc.GetCmdline(pid)
		if len(cmdline) == 0 {
			continue
		}
		appType := guessApplicationType(cmdline)
		if appType != "" {
			appTypes[appType] = struct{}{}
		}
		switch {
		case isJvm(cmdline):
			jvm, jMetrics := jvmMetrics(pid)
			if len(jMetrics) > 0 && !seenJvms[jvm] {
				seenJvms[jvm] = true
				for _, m := range jMetrics {
					ch <- m
				}
			}
		case process.dotNetMonitor != nil:
			appTypes["dotnet"] = struct{}{}
			process.dotNetMonitor.Collect(ch)
		}
	}
	for appType := range appTypes {
		ch <- gauge(metrics.ApplicationType, 1, appType)
	}
	if c.dnsStats.Requests != nil {
		c.dnsStats.Requests.Collect(ch)
	}
	if c.dnsStats.Latency != nil {
		c.dnsStats.Latency.Collect(ch)
	}
	c.l7Stats.collect(ch)

	if !*flags.DisablePinger {
		for ip, rtt := range c.ping() {
			ch <- gauge(metrics.NetLatency, rtt, ip.String())
		}
	}
}

func (c *Container) onProcessStart(pid uint32) *Process {
	c.lock.Lock()
	defer c.lock.Unlock()
	stats, err := TaskstatsPID(pid)
	if err != nil {
		return nil
	}
	c.zombieAt = time.Time{}
	p := NewProcess(pid, stats)
	if p == nil {
		return nil
	}
	c.processes[pid] = p

	if c.startedAt.IsZero() {
		c.startedAt = stats.BeginTime
	} else {
		min := stats.BeginTime
		for _, p := range c.processes {
			if p.StartedAt.Before(min) {
				min = p.StartedAt
			}
		}
		if min.After(c.startedAt) {
			c.restarts++
			c.startedAt = min
		}
	}
	return p
}

func (c *Container) onProcessExit(pid uint32, oomKill bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if p := c.processes[pid]; p != nil {
		p.Close()
	}
	delete(c.processes, pid)
	if len(c.processes) == 0 {
		c.zombieAt = time.Now()
	}
	delete(c.delaysByPid, pid)
	if oomKill {
		c.oomKills++
	}
}

func (c *Container) onFileOpen(pid uint32, fd uint64) {
	mntId, logPath := resolveFd(pid, fd)
	func() {
		if mntId == "" {
			return
		}
		c.lock.Lock()
		_, ok := c.mounts[mntId]
		c.lock.Unlock()
		if ok {
			return
		}
		byMountId := proc.GetMountInfo(pid)
		if byMountId == nil {
			return
		}
		if mi, ok := byMountId[mntId]; ok {
			c.lock.Lock()
			c.mounts[mntId] = mi
			c.lock.Unlock()
		}
	}()
	if logPath != "" {
		c.lock.Lock()
		c.runLogParser(logPath)
		c.lock.Unlock()
	}
}

func (c *Container) onListenOpen(pid uint32, addr netaddr.IPPort, safe bool) {
	if common.PortFilter.ShouldBeSkipped(addr.Port()) {
		return
	}
	if !safe {
		c.lock.Lock()
		defer c.lock.Unlock()
	}
	if _, ok := c.listens[addr]; !ok {
		c.listens[addr] = map[uint32]*ListenDetails{}
	}
	details := &ListenDetails{}
	c.listens[addr][pid] = details

	if addr.IP().IsUnspecified() {
		ns, err := proc.GetNetNs(pid)
		if err != nil {
			if !common.IsNotExist(err) {
				klog.Warningln(err)
			}
			return
		}
		defer ns.Close()
		nsId := ns.UniqueId()
		ips, ok := c.ipsByNs[nsId]
		if !ok {
			if ips, err = proc.GetNsIps(ns); err != nil {
				klog.Warningln(err)
			} else {
				c.ipsByNs[nsId] = ips
			}
		}
		details.NsIPs = ips
	}
}

func (c *Container) onListenClose(pid uint32, addr netaddr.IPPort) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if _, byAddr := c.listens[addr]; byAddr {
		if _, byPid := c.listens[addr][pid]; byPid {
			if details := c.listens[addr][pid]; details != nil {
				details.ClosedAt = time.Now()
			}
		}
	}
}

func (c *Container) onConnectionOpen(pid uint32, fd uint64, src, dst netaddr.IPPort, timestamp uint64, failed bool) {
	if common.PortFilter.ShouldBeSkipped(dst.Port()) {
		return
	}
	p := c.processes[pid]
	if p == nil {
		return
	}
	if dst.IP().IsLoopback() && !p.isHostNs() {
		return
	}
	actualDst, err := c.getActualDestination(p, src, dst)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningf("cannot open NetNs for pid %d: %s", pid, err)
		}
		return
	}
	switch {
	case actualDst == nil:
		actualDst = &dst
	case actualDst.IP().IsLoopback() && !p.isHostNs():
		return
	}
	if common.ConnectionFilter.ShouldBeSkipped(dst.IP(), actualDst.IP()) {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if failed {
		c.connectsFailed[dst]++
	} else {
		c.connectsSuccessful[AddrPair{src: dst, dst: *actualDst}]++
		connection := &ActiveConnection{
			Dest:       dst,
			ActualDest: *actualDst,
			Pid:        pid,
			Fd:         fd,
			Timestamp:  timestamp,
		}
		c.connectionsActive[AddrPair{src: src, dst: dst}] = connection
		c.connectionsByPidFd[PidFd{Pid: pid, Fd: fd}] = connection
	}
	c.connectLastAttempt[dst] = time.Now()
}

func (c *Container) getActualDestination(p *Process, src, dst netaddr.IPPort) (*netaddr.IPPort, error) {
	if actualDst := lookupCiliumConntrackTable(src, dst); actualDst != nil {
		return actualDst, nil
	}
	for _, lb := range c.lbConntracks {
		if actualDst := lb.GetActualDestination(src, dst); actualDst != nil {
			return actualDst, nil
		}
	}
	actualDst := c.hostConntrack.GetActualDestination(src, dst)
	if actualDst != nil {
		return actualDst, nil
	}
	if !p.isHostNs() {
		if c.nsConntrack == nil {
			netNs, err := proc.GetNetNs(p.Pid)
			if err != nil {
				return nil, err
			}
			defer netNs.Close()
			c.nsConntrack, err = NewConntrack(netNs)
			if err != nil {
				return nil, err
			}
		}
		return c.nsConntrack.GetActualDestination(src, dst), nil
	}
	return nil, nil
}

func (c *Container) onConnectionClose(srcDst AddrPair) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	conn := c.connectionsActive[srcDst]
	if conn == nil {
		return false
	}
	conn.Closed = time.Now()
	return true
}

func (c *Container) onDNSRequest(r *l7.RequestData) map[netaddr.IP]string {
	status := r.Status.DNS()
	if status == "" {
		return nil
	}
	t, fqdn, ips := l7.ParseDns(r.Payload)
	if t == "" {
		return nil
	}
	if c.dnsStats.Requests == nil {
		dnsReq := L7Requests[l7.ProtocolDNS]
		c.dnsStats.Requests = prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: dnsReq.Name, Help: dnsReq.Help},
			[]string{"request_type", "domain", "status"},
		)
	}
	if m, _ := c.dnsStats.Requests.GetMetricWithLabelValues(t, fqdn, status); m != nil {
		m.Inc()
	}
	if r.Duration != 0 {
		if c.dnsStats.Latency == nil {
			dnsLatency := L7Latency[l7.ProtocolDNS]
			c.dnsStats.Latency = prometheus.NewHistogram(prometheus.HistogramOpts{Name: dnsLatency.Name, Help: dnsLatency.Help})
		}
		c.dnsStats.Latency.Observe(r.Duration.Seconds())
	}
	ip2fqdn := map[netaddr.IP]string{}
	if fqdn != "" {
		for _, ip := range ips {
			ip2fqdn[ip] = fqdn
		}
	}
	return ip2fqdn
}

func (c *Container) onL7Request(pid uint32, fd uint64, timestamp uint64, r *l7.RequestData) map[netaddr.IP]string {
	c.lock.Lock()
	defer c.lock.Unlock()

	if r.Protocol == l7.ProtocolDNS {
		return c.onDNSRequest(r)
	}

	conn := c.connectionsByPidFd[PidFd{Pid: pid, Fd: fd}]
	if conn == nil {
		return nil
	}
	if timestamp != 0 && conn.Timestamp != timestamp {
		return nil
	}
	stats := c.l7Stats.get(r.Protocol, conn.Dest, conn.ActualDest)
	trace := tracing.NewTrace(string(c.id), conn.ActualDest)
	switch r.Protocol {
	case l7.ProtocolHTTP:
		stats.observe(r.Status.Http(), "", r.Duration)
		method, path := l7.ParseHttp(r.Payload)
		trace.HttpRequest(method, path, r.Status, r.Duration)
	case l7.ProtocolHTTP2:
		if conn.http2Parser == nil {
			conn.http2Parser = l7.NewHttp2Parser()
		}
		requests := conn.http2Parser.Parse(r.Method, r.Payload, uint64(r.Duration))
		for _, req := range requests {
			stats.observe(req.Status.Http(), "", req.Duration)
			trace.Http2Request(req.Method, req.Path, req.Scheme, req.Status, req.Duration)
		}
	case l7.ProtocolPostgres:
		if r.Method != l7.MethodStatementClose {
			stats.observe(r.Status.String(), "", r.Duration)
		}
		if conn.postgresParser == nil {
			conn.postgresParser = l7.NewPostgresParser()
		}
		query := conn.postgresParser.Parse(r.Payload)
		trace.PostgresQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolMysql:
		if r.Method != l7.MethodStatementClose {
			stats.observe(r.Status.String(), "", r.Duration)
		}
		if conn.mysqlParser == nil {
			conn.mysqlParser = l7.NewMysqlParser()
		}
		query := conn.mysqlParser.Parse(r.Payload, r.StatementId)
		trace.MysqlQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolMemcached:
		stats.observe(r.Status.String(), "", r.Duration)
		cmd, items := l7.ParseMemcached(r.Payload)
		trace.MemcachedQuery(cmd, items, r.Status.Error(), r.Duration)
	case l7.ProtocolRedis:
		stats.observe(r.Status.String(), "", r.Duration)
		cmd, args := l7.ParseRedis(r.Payload)
		trace.RedisQuery(cmd, args, r.Status.Error(), r.Duration)
	case l7.ProtocolMongo:
		stats.observe(r.Status.String(), "", r.Duration)
		query := l7.ParseMongo(r.Payload)
		trace.MongoQuery(query, r.Status.Error(), r.Duration)
	case l7.ProtocolKafka, l7.ProtocolCassandra:
		stats.observe(r.Status.String(), "", r.Duration)
	case l7.ProtocolRabbitmq, l7.ProtocolNats:
		stats.observe(r.Status.String(), r.Method.String(), 0)
	case l7.ProtocolDubbo2:
		stats.observe(r.Status.String(), "", r.Duration)
	}
	return nil
}

func (c *Container) onRetransmit(srcDst AddrPair) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	conn, ok := c.connectionsActive[srcDst]
	if !ok {
		return false
	}
	c.retransmits[AddrPair{src: srcDst.dst, dst: conn.ActualDest}]++
	return true
}

func (c *Container) updateDelays() {
	c.delaysLock.Lock()
	defer c.delaysLock.Unlock()
	for pid := range c.processes {
		stats, err := TaskstatsTGID(pid)
		if err != nil {
			continue
		}
		d := c.delaysByPid[pid]
		c.delays.cpu += stats.CPUDelay - d.cpu
		c.delays.disk += stats.BlockIODelay - d.disk
		d.cpu = stats.CPUDelay
		d.disk = stats.BlockIODelay
		c.delaysByPid[pid] = d
	}
}

func (c *Container) getMounts() map[string]map[string]*proc.FSStat {
	if len(c.mounts) == 0 {
		return nil
	}
	res := map[string]map[string]*proc.FSStat{}
	for _, mi := range c.mounts {
		var stat *proc.FSStat
		for pid := range c.processes {
			s, err := proc.StatFS(proc.Path(pid, "root", mi.MountPoint))
			if err == nil {
				stat = &s
				break
			}
		}
		if stat == nil {
			continue
		}
		if _, ok := res[mi.MajorMinor]; !ok {
			res[mi.MajorMinor] = map[string]*proc.FSStat{}
		}
		res[mi.MajorMinor][mi.MountPoint] = stat
	}
	return res
}

func (c *Container) getListens() map[netaddr.IPPort]int {
	res := map[netaddr.IPPort]int{}
	for addr, byPid := range c.listens {
		open := 0
		isHostNs := false
		ips := map[netaddr.IP]bool{}
		for pid, details := range byPid {
			p := c.processes[pid]
			if p == nil {
				continue
			}
			if p.isHostNs() {
				isHostNs = true
			}
			if details.ClosedAt.IsZero() {
				open = 1
			}
			for _, ip := range details.NsIPs {
				ips[ip] = true
			}
		}
		if !addr.IP().IsUnspecified() {
			ips = map[netaddr.IP]bool{addr.IP(): true}
		}
		for ip := range ips {
			if ip.IsLoopback() && !isHostNs {
				continue
			}
			res[netaddr.IPPortFrom(ip, addr.Port())] = open
		}
	}
	return res
}

func (c *Container) getProxiedListens() map[string]map[netaddr.IPPort]struct{} {
	if len(c.metadata.hostListens) == 0 {
		return nil
	}

	hasUnspecified := false
	for _, addrs := range c.metadata.hostListens {
		for _, addr := range addrs {
			if addr.IP().IsUnspecified() {
				hasUnspecified = true
				break
			}
		}
	}

	var hostIps []netaddr.IP
	if hasUnspecified {
		if ns, err := proc.GetHostNetNs(); err != nil {
			klog.Warningln(err)
		} else {
			ips, err := proc.GetNsIps(ns)
			_ = ns.Close()
			if err != nil {
				klog.Warningln(err)
			} else {
				hostIps = ips
			}
		}
	}

	res := map[string]map[netaddr.IPPort]struct{}{}
	for proxy, addrs := range c.metadata.hostListens {
		res[proxy] = map[netaddr.IPPort]struct{}{}
		for _, addr := range addrs {
			if addr.IP().IsUnspecified() {
				for _, ip := range hostIps {
					if addr.IP().Is4() && ip.Is4() || addr.IP().Is6() && ip.Is6() {
						res[proxy][netaddr.IPPortFrom(ip, addr.Port())] = struct{}{}
					}
				}
			} else {
				res[proxy][addr] = struct{}{}
			}
		}
	}
	return res
}

func (c *Container) ping() map[netaddr.IP]float64 {
	netNs := netns.None()
	for pid := range c.processes {
		if pid == agentPid {
			netNs = selfNetNs
			break
		}
		ns, err := proc.GetNetNs(pid)
		if err != nil {
			if !common.IsNotExist(err) {
				klog.Warningln(err)
			}
			continue
		}
		netNs = ns
		defer netNs.Close()
		break
	}
	if !netNs.IsOpen() {
		return nil
	}

	ips := map[netaddr.IP]struct{}{}
	for d := range c.connectsSuccessful {
		ips[d.dst.IP()] = struct{}{}
	}
	for dst := range c.connectsFailed {
		ips[dst.IP()] = struct{}{}
	}
	if len(ips) == 0 {
		return nil
	}
	targets := make([]netaddr.IP, 0, len(ips))
	for ip := range ips {
		targets = append(targets, ip)
	}
	rtt, err := pinger.Ping(netNs, selfNetNs, targets, pingTimeout)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	return rtt
}

func (c *Container) runLogParser(logPath string) {
	if *flags.DisableLogParsing {
		return
	}

	containerId := string(c.id)

	if logPath != "" {
		if c.logParsers[logPath] != nil {
			return
		}
		ch := make(chan logparser.LogEntry)
		parser := logparser.NewParser(ch, nil, logs.OtelLogEmitter(containerId))
		reader, err := logs.NewTailReader(proc.HostPath(logPath), ch)
		if err != nil {
			klog.Warningln(err)
			parser.Stop()
			return
		}
		klog.InfoS("started varlog logparser", "cg", c.cgroup.Id, "log", logPath)
		c.logParsers[logPath] = &LogParser{parser: parser, stop: reader.Stop}
		return
	}

	switch c.cgroup.ContainerType {
	case cgroup.ContainerTypeSystemdService:
		ch := make(chan logparser.LogEntry)
		if err := JournaldSubscribe(c.cgroup, ch); err != nil {
			klog.Warningln(err)
			return
		}
		parser := logparser.NewParser(ch, nil, logs.OtelLogEmitter(containerId))
		stop := func() {
			JournaldUnsubscribe(c.cgroup)
		}
		klog.InfoS("started journald logparser", "cg", c.cgroup.Id)
		c.logParsers["journald"] = &LogParser{parser: parser, stop: stop}

	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeCrio:
		if c.metadata.logPath == "" {
			return
		}
		if parser := c.logParsers["stdout/stderr"]; parser != nil {
			parser.Stop()
			delete(c.logParsers, "stdout/stderr")
		}
		ch := make(chan logparser.LogEntry)
		parser := logparser.NewParser(ch, c.metadata.logDecoder, logs.OtelLogEmitter(containerId))
		reader, err := logs.NewTailReader(proc.HostPath(c.metadata.logPath), ch)
		if err != nil {
			klog.Warningln(err)
			parser.Stop()
			return
		}
		klog.InfoS("started container logparser", "cg", c.cgroup.Id)
		c.logParsers["stdout/stderr"] = &LogParser{parser: parser, stop: reader.Stop}
	}
}

func (c *Container) gc(now time.Time) {
	c.lock.Lock()
	defer c.lock.Unlock()

	established := map[AddrPair]struct{}{}
	establishedDst := map[netaddr.IPPort]struct{}{}
	listens := map[netaddr.IPPort]string{}
	seenNamespaces := map[string]bool{}
	for _, p := range c.processes {
		if seenNamespaces[p.NetNsId()] {
			continue
		}
		sockets, err := proc.GetSockets(p.Pid)
		if err != nil {
			continue
		}
		for _, s := range sockets {
			if s.Listen {
				listens[s.SAddr] = s.Inode
			} else {
				established[AddrPair{src: s.SAddr, dst: s.DAddr}] = struct{}{}
				establishedDst[s.DAddr] = struct{}{}
			}
		}
		seenNamespaces[p.NetNsId()] = true
	}

	for ns := range c.ipsByNs {
		if !seenNamespaces[ns] {
			delete(c.ipsByNs, ns)
		}
	}

	c.revalidateListens(now, listens)

	for srcDst, conn := range c.connectionsActive {
		pidFd := PidFd{Pid: conn.Pid, Fd: conn.Fd}
		if _, ok := established[srcDst]; !ok {
			delete(c.connectionsActive, srcDst)
			if conn == c.connectionsByPidFd[pidFd] {
				delete(c.connectionsByPidFd, pidFd)
			}
			continue
		}
		if !conn.Closed.IsZero() && now.Sub(conn.Closed) > gcInterval {
			delete(c.connectionsActive, srcDst)
			if conn == c.connectionsByPidFd[pidFd] {
				delete(c.connectionsByPidFd, pidFd)
			}
		}
	}
	for dst, at := range c.connectLastAttempt {
		_, active := establishedDst[dst]
		if !active && !at.IsZero() && now.Sub(at) > gcInterval {
			delete(c.connectLastAttempt, dst)
			delete(c.connectsFailed, dst)
			for d := range c.connectsSuccessful {
				if d.src == dst {
					delete(c.connectsSuccessful, d)
				}
			}
			for d := range c.retransmits {
				if d.src == dst {
					delete(c.retransmits, d)
				}
			}
			c.l7Stats.delete(dst)
		}
	}
}

func (c *Container) revalidateListens(now time.Time, actualListens map[netaddr.IPPort]string) {
	for addr, byPid := range c.listens {
		if _, open := actualListens[addr]; open {
			continue
		}
		klog.Warningln("deleting the outdated listen:", addr)
		for _, details := range byPid {
			if details.ClosedAt.IsZero() {
				details.ClosedAt = now
			}
		}
	}

	missingListens := map[netaddr.IPPort]string{}
	for addr, inode := range actualListens {
		byPids, found := c.listens[addr]
		if !found {
			missingListens[addr] = inode
			continue
		}
		open := false
		for _, details := range byPids {
			if details.ClosedAt.IsZero() {
				open = true
				break
			}
		}
		if !open {
			missingListens[addr] = inode
		}
	}

	if len(missingListens) > 0 {
		inodeToPid := map[string]uint32{}
		for pid := range c.processes {
			fds, err := proc.ReadFds(pid)
			if err != nil {
				continue
			}
			for _, fd := range fds {
				if fd.SocketInode != "" {
					inodeToPid[fd.SocketInode] = pid
				}
			}
		}
		for addr, inode := range missingListens {
			pid, found := inodeToPid[inode]
			if !found {
				continue
			}
			klog.Warningln("missing listen found:", addr, pid)
			c.onListenOpen(pid, addr, true)
		}
	}

	for addr, pids := range c.listens {
		for pid, details := range pids {
			if !details.ClosedAt.IsZero() && now.Sub(details.ClosedAt) > gcInterval {
				delete(c.listens[addr], pid)
			}
		}
		if len(c.listens[addr]) == 0 {
			delete(c.listens, addr)
		}
	}
}

func (c *Container) attachTlsUprobes(tracer *ebpftracer.Tracer, pid uint32) {
	p := c.processes[pid]
	if p == nil {
		return
	}
	if !p.openSslUprobesChecked {
		p.uprobes = append(p.uprobes, tracer.AttachOpenSslUprobes(pid)...)
		p.openSslUprobesChecked = true
	}
	if !p.goTlsUprobesChecked {
		p.uprobes = append(p.uprobes, tracer.AttachGoTlsUprobes(pid)...)
		p.goTlsUprobesChecked = true
	}
}

func resolveFd(pid uint32, fd uint64) (mntId string, logPath string) {
	info := proc.GetFdInfo(pid, fd)
	if info == nil {
		return
	}
	switch {
	case info.Flags&os.O_WRONLY == 0 && info.Flags&os.O_RDWR == 0,
		!strings.HasPrefix(info.Dest, "/"),
		strings.HasPrefix(info.Dest, "/proc/"),
		strings.HasPrefix(info.Dest, "/dev/"),
		strings.HasPrefix(info.Dest, "/sys/"),
		strings.HasSuffix(info.Dest, "(deleted)"):
		return
	}
	mntId = info.MntId

	if info.Flags&os.O_WRONLY != 0 && strings.HasPrefix(info.Dest, "/var/log/") &&
		!strings.HasPrefix(info.Dest, "/var/log/pods/") &&
		!strings.HasPrefix(info.Dest, "/var/log/containers/") &&
		!strings.HasPrefix(info.Dest, "/var/log/journal/") {

		logPath = info.Dest
	}
	return
}

func counter(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, labelValues...)
}

func gauge(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labelValues...)
}
