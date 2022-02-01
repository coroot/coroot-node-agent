package containers

import (
	"fmt"
	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netns"
	"k8s.io/klog/v2"
	"os"
	"time"
)

var (
	selfNetNs   = netns.None()
	hostNetNsId = netns.None().UniqueId()
	agentPid    = uint32(os.Getpid())
)

type Registry struct {
	reg prometheus.Registerer

	tracer *ebpftracer.Tracer
	events chan ebpftracer.Event

	containersById       map[ContainerID]*Container
	containersByCgroupId map[string]*Container
	containersByPid      map[uint32]*Container
}

func NewRegistry(reg prometheus.Registerer, kernelVersion string) (*Registry, error) {
	ns, err := proc.GetSelfNetNs()
	if err != nil {
		return nil, err
	}
	selfNetNs = ns
	hostNetNs, err := proc.GetHostNetNs()
	if err != nil {
		return nil, err
	}
	defer hostNetNs.Close()
	hostNetNsId = hostNetNs.UniqueId()

	err = proc.ExecuteInNetNs(hostNetNs, selfNetNs, func() error {
		if err := TaskstatsInit(); err != nil {
			return err
		}
		if err := ConntrackInit(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := DockerdInit(); err != nil {
		klog.Warningln(err)
	}
	if err := ContainerdInit(); err != nil {
		klog.Warningln(err)
	}
	if err := JournaldInit(); err != nil {
		klog.Warningln(err)
	}

	cs := &Registry{
		reg:    reg,
		events: make(chan ebpftracer.Event, 10000),

		containersById:       map[ContainerID]*Container{},
		containersByCgroupId: map[string]*Container{},
		containersByPid:      map[uint32]*Container{},
	}

	go cs.handleEvents(cs.events)
	t, err := ebpftracer.NewTracer(cs.events, kernelVersion)
	if err != nil {
		close(cs.events)
		return nil, err
	}
	cs.tracer = t

	return cs, nil
}

func (r *Registry) Close() {
	r.tracer.Close()
	close(r.events)
}

func (r *Registry) handleEvents(ch <-chan ebpftracer.Event) {
	gcTicker := time.NewTicker(gcInterval)
	defer gcTicker.Stop()
	for {
		select {
		case now := <-gcTicker.C:
			for id, c := range r.containersById {
				if !c.Dead(now) {
					continue
				}
				for cg, cc := range r.containersByCgroupId {
					if cc == c {
						delete(r.containersByCgroupId, cg)
					}
				}
				for pid, cc := range r.containersByPid {
					if cc == c {
						delete(r.containersByPid, pid)
					}
				}
				prometheus.WrapRegistererWith(prometheus.Labels{"container_id": string(id)}, r.reg).Unregister(c)
				delete(r.containersById, id)
				c.Close()
			}

		case e, more := <-ch:
			if !more {
				return
			}
			klog.Infoln(e)
			switch e.Type {
			case ebpftracer.EventTypeProcessStart:
				c, seen := r.containersByPid[e.Pid]
				switch { // possible pids wraparound + missed `process-exit` event
				case c == nil && seen: // ignored
					delete(r.containersByPid, e.Pid)
					continue
				case c != nil: // revalidating by cgroup
					cg, err := proc.ReadCgroup(e.Pid)
					if err != nil || cg.Id != c.cgroup.Id {
						delete(r.containersByPid, e.Pid)
						c.onProcessExit(e.Pid, false)
					}
				}
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onProcessStart(e.Pid)
				}
			case ebpftracer.EventTypeProcessExit:
				if c := r.containersByPid[e.Pid]; c != nil {
					c.onProcessExit(e.Pid, e.Reason == ebpftracer.EventReasonOOMKill)
				}
				delete(r.containersByPid, e.Pid)

			case ebpftracer.EventTypeFileOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onFileOpen(e.Pid, e.Fd)
				}

			case ebpftracer.EventTypeListenOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onListenOpen(e.Pid, e.SrcAddr)
				} else {
					klog.Infoln("TCP listen open from unknown container", e)
				}
			case ebpftracer.EventTypeListenClose:
				if c := r.containersByPid[e.Pid]; c != nil {
					c.onListenClose(e.Pid, e.SrcAddr)
				}

			case ebpftracer.EventTypeConnectionOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onConnectionOpen(e.Pid, e.SrcAddr, e.DstAddr, false)
				} else {
					klog.Infoln("TCP connection from unknown container", e)
				}
			case ebpftracer.EventTypeConnectionError:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onConnectionOpen(e.Pid, e.SrcAddr, e.DstAddr, true)
				} else {
					klog.Infoln("TCP connection error from unknown container", e)
				}
			case ebpftracer.EventTypeConnectionClose:
				srcDst := AddrPair{src: e.SrcAddr, dst: e.DstAddr}
				for _, c := range r.containersById {
					if c.onConnectionClose(srcDst) {
						break
					}
				}
			case ebpftracer.EventTypeTCPRetransmit:
				srcDst := AddrPair{src: e.SrcAddr, dst: e.DstAddr}
				for _, c := range r.containersById {
					if c.onRetransmit(srcDst) {
						break
					}
				}
			}
		}
	}
}

func (r *Registry) getOrCreateContainer(pid uint32) *Container {
	if c, seen := r.containersByPid[pid]; c != nil {
		klog.Infof("got container by pid %d -> %s", pid, c.cgroup.Id)
		return c
	} else if seen { // ignored
		klog.Infof("ignored container for pid %d", pid)
		return nil
	}
	cg, err := proc.ReadCgroup(pid)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningln("failed to read proc cgroup:", err)
		}
		return nil
	}
	klog.Infof("got cgroup by pid %d -> %s", pid, cg.Id)
	if c := r.containersByCgroupId[cg.Id]; c != nil {
		klog.Infof("found container by cgroup pid %d -> %s", pid, cg.Id)
		r.containersByPid[pid] = c
		return c
	}
	md, err := getContainerMetadata(cg)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	id := calcId(cg, md)
	klog.Infof("calculated container id  %d -> %s -> %s", pid, cg.Id, id)
	if id == "" {
		if cg.Id == "/init.scope" && pid != 1 {
			klog.InfoS("ignoring without persisting", "cg", cg.Id, "pid", pid)
		} else {
			klog.InfoS("ignoring", "cg", cg.Id, "pid", pid)
			r.containersByPid[pid] = nil
		}
		return nil
	}
	if c := r.containersById[id]; c != nil {
		klog.Warningln("id conflict:", id)
		if cg.CreatedAt().After(c.cgroup.CreatedAt()) {
			c.cgroup = cg
			c.metadata = md
			c.runLogParser("")
		}
		r.containersByPid[pid] = c
		r.containersByCgroupId[cg.Id] = c
		return c
	}
	c := NewContainer(cg, md)
	klog.InfoS("detected container", "pid", pid, "cg", cg.Id, "id", id)
	if err := prometheus.WrapRegistererWith(prometheus.Labels{"container_id": string(id)}, r.reg).Register(c); err != nil {
		klog.Warningln(err)
		return nil
	}
	r.containersByPid[pid] = c
	r.containersByCgroupId[cg.Id] = c
	r.containersById[id] = c
	return c
}

func calcId(cg *cgroup.Cgroup, md *ContainerMetadata) ContainerID {
	if cg.ContainerType == cgroup.ContainerTypeSystemdService {
		return ContainerID(cg.ContainerId)
	}
	if cg.ContainerType != cgroup.ContainerTypeDocker {
		return ""
	}
	if md.labels["io.kubernetes.pod.name"] != "" {
		pod := md.labels["io.kubernetes.pod.name"]
		namespace := md.labels["io.kubernetes.pod.namespace"]
		name := md.labels["io.kubernetes.container.name"]
		if name == "" || name == "POD" { // skip pause|sandbox containers
			return ""
		}
		return ContainerID(fmt.Sprintf("/k8s/%s/%s/%s", namespace, pod, name))
	}
	if md.name == "" { // should be "pure" dockerd container here
		klog.Warningln("empty dockerd container name for:", cg.ContainerId)
		return ""
	}
	return ContainerID("/docker/" + md.name)
}

func getContainerMetadata(cg *cgroup.Cgroup) (*ContainerMetadata, error) {
	if cg.ContainerType != cgroup.ContainerTypeDocker {
		return &ContainerMetadata{}, nil
	}
	var dockerdErr error
	if dockerdClient != nil {
		md, err := DockerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		klog.Warningln("failed to inspect container %s: %s", cg.ContainerId, err)
		dockerdErr = err
	}
	var containerdErr error
	if containerdClient != nil {
		md, err := ContainerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		klog.Warningln("failed to inspect container %s: %s", cg.ContainerId, err)
		containerdErr = err
	}
	return nil, fmt.Errorf("failed to interact with dockerd (%s) or with containerd (%s)", dockerdErr, containerdErr)
}
