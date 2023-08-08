package containers

import (
	"bytes"
	"fmt"
	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netns"
	"k8s.io/klog/v2"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	selfNetNs         = netns.None()
	hostNetNsId       = netns.None().UniqueId()
	agentPid          = uint32(os.Getpid())
	containerIdRegexp = regexp.MustCompile(`[a-z0-9]{64}`)
)

type Registry struct {
	reg prometheus.Registerer

	tracer *ebpftracer.Tracer
	events chan ebpftracer.Event

	hostConntrack *Conntrack

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
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := cgroup.Init(); err != nil {
		return nil, err
	}
	if err := DockerdInit(); err != nil {
		klog.Warningln(err)
	}
	if err := ContainerdInit(); err != nil {
		klog.Warningln(err)
	}
	if err := CrioInit(); err != nil {
		klog.Warningln(err)
	}
	if err := JournaldInit(); err != nil {
		klog.Warningln(err)
	}
	ct, err := NewConntrack(hostNetNs)
	if err != nil {
		return nil, err
	}

	r := &Registry{
		reg:    reg,
		events: make(chan ebpftracer.Event, 10000),

		hostConntrack: ct,

		containersById:       map[ContainerID]*Container{},
		containersByCgroupId: map[string]*Container{},
		containersByPid:      map[uint32]*Container{},

		tracer: ebpftracer.NewTracer(kernelVersion, *flags.DisableL7Tracing),
	}

	go r.handleEvents(r.events)
	if err = r.tracer.Run(r.events); err != nil {
		close(r.events)
		return nil, err
	}

	return r, nil
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
			for pid, c := range r.containersByPid {
				cg, err := proc.ReadCgroup(pid)
				if err != nil {
					delete(r.containersByPid, pid)
					if c != nil {
						c.onProcessExit(pid, false)
					}
					continue
				}
				if c != nil && cg.Id != c.cgroup.Id {
					delete(r.containersByPid, pid)
					c.onProcessExit(pid, false)
				}
			}

			for id, c := range r.containersById {
				if !c.Dead(now) {
					continue
				}
				klog.Infoln("deleting dead container:", id)
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
				if ok := prometheus.WrapRegistererWith(prometheus.Labels{"container_id": string(id)}, r.reg).Unregister(c); !ok {
					klog.Warningln("failed to unregister container:", id)
				}
				delete(r.containersById, id)
				c.Close()
			}

		case e, more := <-ch:
			if !more {
				return
			}
			switch e.Type {
			case ebpftracer.EventTypeProcessStart:
				c, seen := r.containersByPid[e.Pid]
				switch { // possible pids wraparound + missed `process-exit` event
				case c == nil && seen: // ignored
					delete(r.containersByPid, e.Pid)
				case c != nil: // revalidating by cgroup
					cg, err := proc.ReadCgroup(e.Pid)
					if err != nil || cg.Id != c.cgroup.Id {
						delete(r.containersByPid, e.Pid)
						c.onProcessExit(e.Pid, false)
					}
				}
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					uprobes := r.tracer.AttachGoTlsUprobes(e.Pid)
					c.onProcessStart(e.Pid, uprobes)
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
					c.onListenOpen(e.Pid, e.SrcAddr, false)
				} else {
					klog.Infoln("TCP listen open from unknown container", e)
				}
			case ebpftracer.EventTypeListenClose:
				if c := r.containersByPid[e.Pid]; c != nil {
					c.onListenClose(e.Pid, e.SrcAddr)
				}

			case ebpftracer.EventTypeConnectionOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onConnectionOpen(e.Pid, e.Fd, e.SrcAddr, e.DstAddr, e.Timestamp, false)
				} else {
					klog.Infoln("TCP connection from unknown container", e)
				}
			case ebpftracer.EventTypeConnectionError:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onConnectionOpen(e.Pid, e.Fd, e.SrcAddr, e.DstAddr, 0, true)
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
			case ebpftracer.EventTypeL7Request:
				if e.L7Request == nil {
					continue
				}
				if c := r.containersByPid[e.Pid]; c != nil {
					c.onL7Request(e.Pid, e.Fd, e.Timestamp, e.L7Request)
				}
			}
		}
	}
}

func (r *Registry) getOrCreateContainer(pid uint32) *Container {
	if c, seen := r.containersByPid[pid]; c != nil {
		return c
	} else if seen { // ignored
		return nil
	}
	cg, err := proc.ReadCgroup(pid)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningln("failed to read proc cgroup:", err)
		}
		return nil
	}
	if c := r.containersByCgroupId[cg.Id]; c != nil {
		r.containersByPid[pid] = c
		return c
	}
	if cg.ContainerType == cgroup.ContainerTypeSandbox {
		cmdline := proc.GetCmdline(pid)
		parts := bytes.Split(cmdline, []byte{0})
		if len(parts) > 0 {
			cmd := parts[0]
			lastArg := parts[len(parts)-1]
			if (bytes.HasSuffix(cmd, []byte("runsc-sandbox")) || bytes.HasSuffix(cmd, []byte("runsc"))) && containerIdRegexp.Match(lastArg) {
				cg.ContainerId = string(lastArg)
			}
		}
	}
	md, err := getContainerMetadata(cg)
	if err != nil {
		klog.Warningf("failed to get container metadata for pid %d -> %s: %s", pid, cg.Id, err)
		return nil
	}
	id := calcId(cg, md)
	klog.Infof("calculated container id %d -> %s -> %s", pid, cg.Id, id)
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
			if c.nsConntrack != nil {
				_ = c.nsConntrack.Close()
				c.nsConntrack = nil
			}
		}
		r.containersByPid[pid] = c
		r.containersByCgroupId[cg.Id] = c
		return c
	}
	c, err := NewContainer(id, cg, md, r.hostConntrack, pid)
	if err != nil {
		klog.Warningf("failed to create container pid=%d cg=%s id=%s: %s", pid, cg.Id, id, err)
		return nil
	}

	klog.InfoS("detected a new container", "pid", pid, "cg", cg.Id, "id", id)
	if err := prometheus.WrapRegistererWith(prometheus.Labels{"container_id": string(id)}, r.reg).Register(c); err != nil {
		klog.Warningln("failed to register container:", err)
		return nil
	}
	r.containersByPid[pid] = c
	r.containersByCgroupId[cg.Id] = c
	r.containersById[id] = c
	return c
}

func calcId(cg *cgroup.Cgroup, md *ContainerMetadata) ContainerID {
	if cg.ContainerType == cgroup.ContainerTypeSystemdService {
		if strings.HasPrefix(cg.ContainerId, "/system.slice/crio-conmon-") {
			return ""
		}
		return ContainerID(cg.ContainerId)
	}
	switch cg.ContainerType {
	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeSandbox, cgroup.ContainerTypeCrio:
	default:
		return ""
	}
	if cg.ContainerId == "" {
		return ""
	}
	if md.labels["io.kubernetes.pod.name"] != "" {
		pod := md.labels["io.kubernetes.pod.name"]
		namespace := md.labels["io.kubernetes.pod.namespace"]
		name := md.labels["io.kubernetes.container.name"]
		if cg.ContainerType == cgroup.ContainerTypeSandbox {
			name = "sandbox"
		}
		if name == "" || name == "POD" { // skip pause containers
			return ""
		}
		return ContainerID(fmt.Sprintf("/k8s/%s/%s/%s", namespace, pod, name))
	}
	if taskNameParts := strings.SplitN(md.labels["com.docker.swarm.task.name"], ".", 3); len(taskNameParts) == 3 {
		namespace := md.labels["com.docker.stack.namespace"]
		service := md.labels["com.docker.swarm.service.name"]
		if namespace != "" {
			service = strings.TrimPrefix(service, namespace+"_")
		}
		if namespace == "" {
			namespace = "_"
		}
		return ContainerID(fmt.Sprintf("/swarm/%s/%s/%s", namespace, service, taskNameParts[1]))
	}
	if md.name == "" { // should be "pure" dockerd container here
		klog.Warningln("empty dockerd container name for:", cg.ContainerId)
		return ""
	}
	return ContainerID("/docker/" + md.name)
}

func getContainerMetadata(cg *cgroup.Cgroup) (*ContainerMetadata, error) {
	switch cg.ContainerType {
	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeSandbox, cgroup.ContainerTypeCrio:
	default:
		return &ContainerMetadata{}, nil
	}
	if cg.ContainerId == "" {
		return &ContainerMetadata{}, nil
	}
	if cg.ContainerType == cgroup.ContainerTypeCrio {
		return CrioInspect(cg.ContainerId)
	}
	var dockerdErr error
	if dockerdClient != nil {
		md, err := DockerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		dockerdErr = err
	}
	var containerdErr error
	if containerdClient != nil {
		md, err := ContainerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		containerdErr = err
	}
	return nil, fmt.Errorf("failed to interact with dockerd (%s) or with containerd (%s)", dockerdErr, containerdErr)
}
