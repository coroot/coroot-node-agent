//go:build windows

package containers

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/etwtracer"
	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

const (
	windowsContainerRuntimeTimeout = 5 * time.Second
	cronjobPodScheduleWindow       = 7 * 24 * time.Hour
)

var (
	cronjobPodName = regexp.MustCompile(`([a-z0-9-]+)-([0-9]{8})-[bcdfghjklmnpqrstvwxz2456789]{5}`)

	windowsContainerInfoDesc = prometheus.NewDesc(
		"container_info",
		"Meta information about the container",
		[]string{"container_id", "app_id", "image", "systemd_triggered_by", "systemd_type"}, nil,
	)
	windowsContainerRestartsDesc = prometheus.NewDesc(
		"container_restarts_total",
		"Number of times the container was restarted",
		[]string{"container_id", "app_id"}, nil,
	)
)

type ContainerID string

type ProcessInfo struct {
	Pid         uint32
	ContainerId ContainerID
	StartedAt   time.Time
	Flags       proc.Flags
}

type Registry struct {
	sources []windowsContainerSource
	network *windowsNetworkState
	tracer  *etwtracer.Tracer
}

type windowsContainerSource interface {
	Name() string
	Containers(ctx context.Context) ([]windowsContainer, error)
	Close() error
}

type windowsContainerProcessSource interface {
	ContainerProcesses(ctx context.Context, containers []windowsContainer) ([]windowsContainerProcess, error)
}

type windowsContainer struct {
	ID           ContainerID
	AppID        string
	Runtime      string
	RawID        string
	Name         string
	Image        string
	Isolation    string
	RestartCount int
	Pid          uint32
	StartedAt    time.Time
}

func NewRegistry(reg prometheus.Registerer, processInfoCh chan<- ProcessInfo, profilingUpdateCh chan *ProfilingUpdate, gpuProcessUsageSampleChan chan gpu.ProcessUsageSample) (*Registry, error) {
	r := &Registry{sources: detectWindowsContainerSources(), network: newWindowsNetworkState()}
	if len(r.sources) == 0 {
		klog.Warningln("no supported Windows container runtime detected; container metrics disabled")
	}
	r.tracer = etwtracer.NewTracer()
	if err := r.tracer.Start(); err != nil {
		klog.Warningf("Windows ETW tracer unavailable; network metrics disabled: %s", err)
		r.tracer.Close()
		r.tracer = nil
	} else {
		go r.handleETWEvents(r.tracer.Events())
	}
	if err := reg.Register(r); err != nil {
		if r.tracer != nil {
			r.tracer.Close()
		}
		return nil, err
	}
	return r, nil
}

func (r *Registry) Describe(ch chan<- *prometheus.Desc) {
	ch <- windowsContainerInfoDesc
	ch <- windowsContainerRestartsDesc
	r.network.Describe(ch)
}

func (r *Registry) Collect(ch chan<- prometheus.Metric) {
	seen := map[ContainerID]string{}
	var processes []windowsContainerProcess
	for _, source := range r.sources {
		ctx, cancel := context.WithTimeout(context.Background(), windowsContainerRuntimeTimeout)
		containers, err := source.Containers(ctx)
		if err != nil {
			cancel()
			klog.Warningf("failed to list Windows containers from %s: %s", source.Name(), err)
			continue
		}
		var reportable []windowsContainer
		for _, c := range containers {
			if c.ID == "" {
				continue
			}
			if previous := seen[c.ID]; previous != "" {
				klog.Warningf("container identity %q reported by both %s and %s; ignoring duplicate from %s", c.ID, previous, source.Name(), source.Name())
				continue
			}
			if common.ContainerFilter.ShouldBeSkipped(string(c.ID)) {
				klog.InfoS("skipping due to user-defined settings", "id", c.ID, "runtime", source.Name())
				continue
			}
			seen[c.ID] = source.Name()
			reportable = append(reportable, c)
			ch <- prometheus.MustNewConstMetric(windowsContainerInfoDesc, prometheus.GaugeValue, 1, string(c.ID), c.AppID, c.Image, "", "")
			ch <- prometheus.MustNewConstMetric(windowsContainerRestartsDesc, prometheus.CounterValue, float64(c.RestartCount), string(c.ID), c.AppID)
		}
		if processSource, ok := source.(windowsContainerProcessSource); ok {
			ps, err := processSource.ContainerProcesses(ctx, reportable)
			if err != nil {
				klog.Warningf("failed to list Windows container processes from %s: %s", source.Name(), err)
			} else {
				processes = append(processes, ps...)
			}
		}
		cancel()
	}
	r.network.ReplaceProcesses(processes)
	r.network.Collect(ch)
}

func (r *Registry) Close() {
	if r.tracer != nil {
		r.tracer.Close()
	}
	for _, source := range r.sources {
		if err := source.Close(); err != nil {
			klog.Warningf("failed to close Windows container source %s: %s", source.Name(), err)
		}
	}
}

func (r *Registry) handleETWEvents(events <-chan etwtracer.Event) {
	for event := range events {
		r.network.Observe(event)
	}
}

func detectWindowsContainerSources() []windowsContainerSource {
	var sources []windowsContainerSource
	dockerSource, err := newWindowsDockerSource()
	if err != nil {
		klog.Warningf("Windows Docker runtime unavailable: %s", err)
	} else {
		sources = append(sources, dockerSource)
	}
	return sources
}

type windowsDockerSource struct {
	client *client.Client
}

func newWindowsDockerSource() (*windowsDockerSource, error) {
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), windowsContainerRuntimeTimeout)
	defer cancel()
	ping, err := c.Ping(ctx)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if ping.OSType != "" && !strings.EqualFold(ping.OSType, "windows") {
		_ = c.Close()
		return nil, fmt.Errorf("Docker engine reports OSType=%q; Windows containers require a Windows engine", ping.OSType)
	}
	c.NegotiateAPIVersion(ctx)
	klog.Infof("using Windows Docker engine API version %s", ping.APIVersion)
	return &windowsDockerSource{client: c}, nil
}

func (s *windowsDockerSource) Name() string { return "dockerd" }

func (s *windowsDockerSource) Close() error { return s.client.Close() }

func (s *windowsDockerSource) Containers(ctx context.Context) ([]windowsContainer, error) {
	items, err := s.client.ContainerList(ctx, dockercontainer.ListOptions{All: false})
	if err != nil {
		return nil, err
	}
	res := make([]windowsContainer, 0, len(items))
	for _, item := range items {
		inspect, err := s.client.ContainerInspect(ctx, item.ID)
		if err != nil {
			klog.Warningf("failed to inspect Windows Docker container %s: %s", item.ID, err)
			continue
		}
		c, ok := dockerContainerFromInspect(item, inspect)
		if !ok {
			continue
		}
		res = append(res, c)
	}
	return res, nil
}

func (s *windowsDockerSource) ContainerProcesses(ctx context.Context, containers []windowsContainer) ([]windowsContainerProcess, error) {
	var res []windowsContainerProcess
	for _, c := range containers {
		if c.RawID == "" || !strings.EqualFold(c.Isolation, "process") {
			continue
		}
		top, err := s.client.ContainerTop(ctx, c.RawID, nil)
		if err != nil {
			return res, err
		}
		res = append(res, windowsContainerProcessesFromTop(c, top)...)
	}
	return res, nil
}

func windowsContainerProcessesFromTop(c windowsContainer, top dockercontainer.ContainerTopOKBody) []windowsContainerProcess {
	pidColumn := -1
	for i, title := range top.Titles {
		if strings.EqualFold(title, "PID") {
			pidColumn = i
			break
		}
	}
	if pidColumn < 0 {
		return nil
	}
	var res []windowsContainerProcess
	for _, row := range top.Processes {
		if pidColumn >= len(row) {
			continue
		}
		pid, err := strconv.ParseUint(strings.TrimSpace(row[pidColumn]), 10, 32)
		if err != nil || pid == 0 {
			continue
		}
		res = append(res, windowsContainerProcess{Pid: uint32(pid), ContainerID: c.ID, AppID: c.AppID})
	}
	return res
}

func dockerContainerFromInspect(item types.Container, inspect types.ContainerJSON) (windowsContainer, bool) {
	if inspect.State != nil && !inspect.State.Running {
		return windowsContainer{}, false
	}
	name := strings.TrimPrefix(inspect.Name, "/")
	if name == "" && len(item.Names) > 0 {
		name = strings.TrimPrefix(item.Names[0], "/")
	}
	labels := map[string]string{}
	if inspect.Config != nil {
		for k, v := range inspect.Config.Labels {
			labels[k] = v
		}
	}
	if len(labels) == 0 {
		for k, v := range item.Labels {
			labels[k] = v
		}
	}
	env := map[string]string{}
	if inspect.Config != nil {
		env = parseDockerEnv(inspect.Config.Env)
	}
	image := item.Image
	if inspect.Config != nil && inspect.Config.Image != "" {
		image = inspect.Config.Image
	}
	id := windowsContainerID("docker", name, labels, env)
	if id == "" {
		return windowsContainer{}, false
	}
	var pid uint32
	var startedAt time.Time
	var isolation string
	if inspect.State != nil {
		if inspect.State.Pid > 0 {
			pid = uint32(inspect.State.Pid)
		}
		if t, err := time.Parse(time.RFC3339Nano, inspect.State.StartedAt); err == nil {
			startedAt = t
		}
	}
	if inspect.HostConfig != nil {
		isolation = string(inspect.HostConfig.Isolation)
	}
	return windowsContainer{
		ID:           id,
		AppID:        appIDForContainerID(id),
		Runtime:      "docker",
		RawID:        firstNonEmpty(inspect.ID, item.ID),
		Name:         name,
		Image:        image,
		Isolation:    isolation,
		RestartCount: inspect.RestartCount,
		Pid:          pid,
		StartedAt:    startedAt,
	}, true
}

func windowsContainerID(runtimeName, name string, labels, env map[string]string) ContainerID {
	if labels["io.kubernetes.pod.name"] != "" {
		pod := labels["io.kubernetes.pod.name"]
		namespace := labels["io.kubernetes.pod.namespace"]
		containerName := labels["io.kubernetes.container.name"]
		if containerName == "" || containerName == "POD" {
			return ""
		}
		if g := cronjobPodName.FindStringSubmatch(pod); len(g) == 3 {
			now := time.Now()
			scheduledMinutes, _ := strconv.ParseUint(g[2], 10, 64)
			scheduledAt := time.Unix(int64(scheduledMinutes)*60, 0)
			if scheduledAt.After(now.Add(-cronjobPodScheduleWindow)) && scheduledAt.Before(now.Add(cronjobPodScheduleWindow)) {
				return ContainerID(fmt.Sprintf("/k8s-cronjob/%s/%s/%s", namespace, g[1], containerName))
			}
		}
		return ContainerID(fmt.Sprintf("/k8s/%s/%s/%s", namespace, pod, containerName))
	}
	if taskNameParts := strings.SplitN(labels["com.docker.swarm.task.name"], ".", 3); len(taskNameParts) == 3 {
		namespace := labels["com.docker.stack.namespace"]
		service := labels["com.docker.swarm.service.name"]
		if namespace != "" {
			service = strings.TrimPrefix(service, namespace+"_")
		}
		if namespace == "" {
			namespace = "_"
		}
		return ContainerID(fmt.Sprintf("/swarm/%s/%s/%s", namespace, service, taskNameParts[1]))
	}
	if env != nil {
		allocID := env["NOMAD_ALLOC_ID"]
		group := env["NOMAD_GROUP_NAME"]
		job := env["NOMAD_JOB_NAME"]
		namespace := env["NOMAD_NAMESPACE"]
		task := env["NOMAD_TASK_NAME"]
		if allocID != "" && group != "" && job != "" && namespace != "" && task != "" {
			return ContainerID(fmt.Sprintf("/nomad/%s/%s/%s/%s/%s", namespace, job, group, allocID, task))
		}
	}
	if name == "" {
		return ""
	}
	switch runtimeName {
	case "docker":
		return ContainerID("/docker/" + name)
	case "containerd":
		return ContainerID("/containerd/" + name)
	default:
		return ContainerID("/" + runtimeName + "/" + name)
	}
}

func appIDForContainerID(id ContainerID) string {
	appID := common.ContainerIdToOtelServiceName(string(id))
	if appID == string(id) {
		return ""
	}
	return appID
}

func parseDockerEnv(values []string) map[string]string {
	env := map[string]string{}
	for _, value := range values {
		k, v, ok := strings.Cut(value, "=")
		if !ok {
			continue
		}
		env[k] = v
	}
	return env
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

const (
	RuntimeJvm = "jvm"
	RuntimeGo  = "go"
)

type ProfilingUpdate struct {
	Pid             uint32
	Runtime         string
	AllocBytes      int64
	AllocObjects    int64
	LockContentions int64
	LockTimeNs      int64
}
