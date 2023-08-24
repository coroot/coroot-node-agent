package containers

import (
	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
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
	"os"
	"strings"
	"sync"
	"time"
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
	ActualDest netaddr.IPPort
	Pid        uint32
	Fd         uint64
	Timestamp  uint64
	Closed     time.Time

	PreparedStatements map[string]string
}

type L7Stats struct {
	Requests *prometheus.CounterVec
	Latency  prometheus.Histogram
}

type ListenDetails struct {
	ClosedAt time.Time
	NsIPs    []netaddr.IP
}

type Process struct {
	Pid       uint32
	StartedAt time.Time
	NetNsId   string

	uprobes               []link.Link
	goTlsUprobesChecked   bool
	openSslUprobesChecked bool
}

func (p *Process) isHostNs() bool {
	return p.NetNsId == hostNetNsId
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

	connectsSuccessful map[AddrPair]int64           // dst:actual_dst -> count
	connectsFailed     map[netaddr.IPPort]int64     // dst -> count
	connectLastAttempt map[netaddr.IPPort]time.Time // dst -> time
	connectionsActive  map[AddrPair]*ActiveConnection
	retransmits        map[AddrPair]int64 // dst:actual_dst -> count

	l7Stats map[ebpftracer.L7Protocol]map[AddrPair]*L7Stats // protocol -> dst:actual_dst -> stats

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

		connectsSuccessful: map[AddrPair]int64{},
		connectsFailed:     map[netaddr.IPPort]int64{},
		connectLastAttempt: map[netaddr.IPPort]time.Time{},
		connectionsActive:  map[AddrPair]*ActiveConnection{},
		retransmits:        map[AddrPair]int64{},
		l7Stats:            map[ebpftracer.L7Protocol]map[AddrPair]*L7Stats{},

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
	for c, conn := range c.connectionsActive {
		if !conn.Closed.IsZero() {
			continue
		}
		connections[AddrPair{src: c.dst, dst: conn.ActualDest}]++
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
	for pid := range c.processes {
		cmdline := proc.GetCmdline(pid)
		if len(cmdline) == 0 {
			continue
		}
		appType := guessApplicationType(cmdline)
		if appType != "" {
			appTypes[appType] = struct{}{}
		}
		if isJvm(cmdline) {
			jvm, jMetrics := jvmMetrics(pid)
			if len(jMetrics) > 0 && !seenJvms[jvm] {
				seenJvms[jvm] = true
				for _, m := range jMetrics {
					ch <- m
				}
			}
		}
	}
	for appType := range appTypes {
		ch <- gauge(metrics.ApplicationType, 1, appType)
	}

	for _, protoStats := range c.l7Stats {
		for _, s := range protoStats {
			if s.Requests != nil {
				s.Requests.Collect(ch)
			}
			if s.Latency != nil {
				s.Latency.Collect(ch)
			}
		}
	}

	if !*flags.DisablePinger {
		for ip, rtt := range c.ping() {
			ch <- gauge(metrics.NetLatency, rtt, ip.String())
		}
	}
}

func (c *Container) onProcessStart(pid uint32) {
	c.lock.Lock()
	defer c.lock.Unlock()
	stats, err := TaskstatsPID(pid)
	if err != nil {
		return
	}
	ns, err := proc.GetNetNs(pid)
	if err != nil {
		return
	}
	defer ns.Close()
	c.zombieAt = time.Time{}
	c.processes[pid] = &Process{Pid: pid, StartedAt: stats.BeginTime, NetNsId: ns.UniqueId()}

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
}

func (c *Container) onProcessExit(pid uint32, oomKill bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if p := c.processes[pid]; p != nil {
		for _, u := range p.uprobes {
			_ = u.Close()
		}
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
		if ips, err := proc.GetNsIps(ns); err != nil {
			klog.Warningln(err)
		} else {
			details.NsIPs = ips
		}
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
	p := c.processes[pid]
	if p == nil {
		return
	}
	if dst.IP().IsLoopback() && !p.isHostNs() {
		return
	}
	whitelisted := false
	for _, prefix := range flags.ExternalNetworksWhitelist {
		if prefix.Contains(dst.IP()) {
			whitelisted = true
			break
		}
	}
	if !whitelisted && !common.IsIpPrivate(dst.IP()) && !dst.IP().IsLoopback() {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if failed {
		c.connectsFailed[dst]++
	} else {
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
		c.connectsSuccessful[AddrPair{src: dst, dst: *actualDst}]++
		c.connectionsActive[AddrPair{src: src, dst: dst}] = &ActiveConnection{
			ActualDest:         *actualDst,
			Pid:                pid,
			Fd:                 fd,
			Timestamp:          timestamp,
			PreparedStatements: map[string]string{},
		}
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

func (c *Container) onL7Request(pid uint32, fd uint64, timestamp uint64, r *ebpftracer.L7Request) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for dest, conn := range c.connectionsActive {
		if conn.Pid == pid && conn.Fd == fd && (timestamp == 0 || conn.Timestamp == timestamp) {
			key := AddrPair{src: dest.dst, dst: conn.ActualDest}
			stats := c.l7Stats[r.Protocol]
			if stats == nil {
				stats = map[AddrPair]*L7Stats{}
				c.l7Stats[r.Protocol] = stats
			}
			tracing.HandleL7Request(string(c.id), conn.ActualDest, r, conn.PreparedStatements)
			if r.Method == ebpftracer.L7MethodStatementClose {
				return
			}
			s := stats[key]
			if s == nil {
				constLabels := map[string]string{"destination": key.src.String(), "actual_destination": key.dst.String()}
				s = &L7Stats{}
				cOpts, ok := L7Requests[r.Protocol]
				if !ok {
					klog.Warningln("cannot find metric description for L7 protocol: %s", r.Protocol.String())
					return
				}
				if cOpts.Name != "" {
					labels := []string{"status"}
					if r.Protocol == ebpftracer.L7ProtocolRabbitmq || r.Protocol == ebpftracer.L7ProtocolNats {
						labels = append(labels, "method")
					}
					s.Requests = prometheus.NewCounterVec(
						prometheus.CounterOpts{Name: cOpts.Name, Help: cOpts.Help, ConstLabels: constLabels}, labels,
					)
				}
				hOpts, ok := L7Latency[r.Protocol]
				if !ok {
					klog.Warningln("cannot find metric description for L7 protocol: %s", r.Protocol.String())
					return
				}
				if hOpts.Name != "" {
					s.Latency = prometheus.NewHistogram(
						prometheus.HistogramOpts{Name: hOpts.Name, Help: hOpts.Help, ConstLabels: constLabels},
					)
				}
				stats[key] = s
			}
			if s.Requests != nil {
				if r.Protocol == ebpftracer.L7ProtocolRabbitmq || r.Protocol == ebpftracer.L7ProtocolNats {
					s.Requests.WithLabelValues(r.StatusString(), r.Method.String()).Inc()
				} else {
					s.Requests.WithLabelValues(r.StatusString()).Inc()
				}
			}
			if s.Latency != nil {
				s.Latency.Observe(r.Duration.Seconds())
			}
			return
		}
	}
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

	if logPath != "" {
		if c.logParsers[logPath] != nil {
			return
		}
		ch := make(chan logparser.LogEntry)
		parser := logparser.NewParser(ch, nil)
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
		parser := logparser.NewParser(ch, nil)
		stop := func() {
			JournaldUnsubscribe(c.cgroup)
		}
		klog.InfoS("started journald logparser", "cg", c.cgroup.Id)
		c.logParsers["journald"] = &LogParser{parser: parser, stop: stop}

	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd:
		if c.metadata.logPath == "" {
			return
		}
		if parser := c.logParsers["stdout/stderr"]; parser != nil {
			parser.Stop()
			delete(c.logParsers, "stdout/stderr")
		}
		ch := make(chan logparser.LogEntry)
		parser := logparser.NewParser(ch, c.metadata.logDecoder)
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
		if seenNamespaces[p.NetNsId] {
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
		seenNamespaces[p.NetNsId] = true
	}

	c.revalidateListens(now, listens)

	for srcDst, conn := range c.connectionsActive {
		if _, ok := established[srcDst]; !ok {
			delete(c.connectionsActive, srcDst)
			continue
		}
		if !conn.Closed.IsZero() && now.Sub(conn.Closed) > gcInterval {
			delete(c.connectionsActive, srcDst)
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
			for _, protoStats := range c.l7Stats {
				for d := range protoStats {
					if d.src == dst {
						delete(protoStats, d)
					}
				}
			}
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
