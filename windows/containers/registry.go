//go:build windows

package containers

import (
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/windows/nettracer"
	"github.com/coroot/logparser"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

const containerRetention = 5 * time.Minute

type Registry struct {
	lock           sync.Mutex
	containers     map[string]*Container
	pidToContainer map[uint32]*Container
	docker         *dockerClient

	eventLogReader *logs.EventLogReader
	netTracker     *nettracer.Tracker

	reg               prometheus.Registerer
	discoveryInterval time.Duration
}

func NewRegistry(discoveryInterval time.Duration) *Registry {
	r := &Registry{
		containers:        make(map[string]*Container),
		discoveryInterval: discoveryInterval,
		docker:            newDockerClient(),
	}
	r.netTracker = nettracer.NewTracker(r.routeDNSRequest)

	if !*flags.DisableLogParsing {
		reader, err := logs.NewEventLogReader("Application")
		if err != nil {
			klog.Warningln("failed to start event log reader:", err)
		} else {
			r.eventLogReader = reader
			go r.eventLogPoller()
		}
	}

	return r
}

func containerID(kind Kind, name string) string {
	switch kind {
	case KindDocker:
		return "/docker/" + name
	default:
		return "/win/" + strings.ReplaceAll(name, "$", "_")
	}
}

func (r *Registry) routeDNSRequest(req *nettracer.DNSRequest) {
	r.lock.Lock()
	c := r.pidToContainer[req.PID]
	r.lock.Unlock()
	if c != nil {
		c.observeDNS(req)
	}
}

func (r *Registry) eventLogPoller() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		r.lock.Lock()
		r.processEventLogs()
		r.lock.Unlock()
	}
}

func (r *Registry) processEventLogs() {
	if r.eventLogReader == nil {
		return
	}

	entries := r.eventLogReader.Poll()
	for _, entry := range entries {
		c := r.pidToContainer[entry.PID]
		if c == nil {
			c = r.containers[containerID(KindService, entry.Provider)]
		}
		if c == nil {
			continue
		}
		select {
		case c.eventLogInput() <- logparser.LogEntry{
			Timestamp: entry.Timestamp,
			Content:   entry.Message,
			Level:     entry.Level,
		}:
		default:
		}
	}
}

func (r *Registry) discover() {
	discovered := append(discoverServices(), r.docker.list()...)

	var toRegister, toUnregister []*Container
	var toStartTail, toStopTail []*Container

	r.lock.Lock()

	seen := make(map[string]bool, len(discovered))
	for _, c := range discovered {
		if common.ContainerFilter.ShouldBeSkipped(c.ID) {
			continue
		}
		seen[c.ID] = true
		if container, ok := r.containers[c.ID]; ok {
			container.lock.Lock()
			if c.logPath != "" && (!container.goneAt.IsZero() || container.logPath != c.logPath) {
				toStartTail = append(toStartTail, container)
			}
			if c.PID != 0 {
				if container.PID != 0 && container.PID != c.PID {
					container.RestartCount++
				}
				container.PID = c.PID
			}
			container.PIDs = c.PIDs
			container.ips = c.ips
			container.hyperv = c.hyperv
			container.StartedAt = c.StartedAt
			container.DisplayName = c.DisplayName
			container.Image = c.Image
			container.logPath = c.logPath
			container.goneAt = time.Time{}
			container.lock.Unlock()
		} else {
			c.registry = r
			r.containers[c.ID] = c
			toRegister = append(toRegister, c)
			toStartTail = append(toStartTail, c)
		}
	}

	for id, c := range r.containers {
		if seen[id] {
			continue
		}
		if c.goneAt.IsZero() {
			c.lock.Lock()
			c.goneAt = time.Now()
			c.PIDs = nil
			c.lock.Unlock()
			toStopTail = append(toStopTail, c)
		} else if time.Since(c.goneAt) > containerRetention {
			delete(r.containers, id)
			toUnregister = append(toUnregister, c)
		}
	}

	rootCount := map[uint32]int{}
	for _, c := range r.containers {
		if c.active() {
			rootCount[c.PID]++
		}
	}
	for _, c := range r.containers {
		c.lock.Lock()
		c.shared = c.active() && rootCount[c.PID] > 1
		c.lock.Unlock()
	}

	claims := map[uint32]int{}
	for _, c := range r.containers {
		for _, pid := range c.PIDs {
			claims[pid]++
		}
	}
	idx := map[uint32]*Container{}
	for _, c := range r.containers {
		for _, pid := range c.PIDs {
			if claims[pid] == 1 {
				idx[pid] = c
			}
		}
	}
	r.pidToContainer = idx

	r.lock.Unlock()

	if r.netTracker != nil {
		r.netTracker.RefreshConnections()
		r.netTracker.RetainPIDs(claims)
	}

	for _, c := range toRegister {
		wreg := prometheus.WrapRegistererWith(prometheus.Labels{"container_id": c.ID}, r.reg)
		if err := wreg.Register(c); err != nil {
			klog.Warningf("failed to register collector for %s: %v", c.ID, err)
		}
	}
	for _, c := range toUnregister {
		prometheus.WrapRegistererWith(prometheus.Labels{"container_id": c.ID}, r.reg).Unregister(c)
		c.closeLogs()
	}

	for _, c := range toStartTail {
		c.startLogTailer()
	}
	for _, c := range toStopTail {
		c.stopLogTailer()
	}
}

func (r *Registry) Start(registerer prometheus.Registerer) {
	r.reg = registerer
	go r.discoveryLoop()
}

func (r *Registry) discoveryLoop() {
	r.discover()
	ticker := time.NewTicker(r.discoveryInterval)
	defer ticker.Stop()
	for range ticker.C {
		r.discover()
	}
}

func (r *Registry) Stop() {
	if r.netTracker != nil {
		r.netTracker.Stop()
	}
	if r.eventLogReader != nil {
		r.eventLogReader.Close()
	}
	r.lock.Lock()
	containers := make([]*Container, 0, len(r.containers))
	for _, c := range r.containers {
		containers = append(containers, c)
	}
	r.lock.Unlock()
	for _, c := range containers {
		c.closeLogs()
	}
}
