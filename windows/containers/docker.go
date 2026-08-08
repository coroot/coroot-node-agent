//go:build windows

package containers

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"k8s.io/klog/v2"
)

const dockerTimeout = 5 * time.Second

var errDockerUnavailable = errors.New("docker engine not available")

type dockerClient struct {
	mu     sync.Mutex
	client *client.Client
}

func newDockerClient() *dockerClient { return &dockerClient{} }

func (d *dockerClient) ensure() *client.Client {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client != nil {
		return d.client
	}
	c, err := client.New(
		client.WithHost("npipe:////./pipe/docker_engine"),
	)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()
	if _, err := c.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		c.Close()
		return nil
	}
	klog.Infoln("docker: connected to engine via named pipe")
	d.client = c
	return c
}

func (d *dockerClient) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client != nil {
		d.client.Close()
		d.client = nil
	}
}

func (d *dockerClient) list() []*Container {
	c := d.ensure()
	if c == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	list, err := c.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		klog.V(2).Infof("docker: ContainerList failed: %v", err)
		d.reset()
		return nil
	}

	trees := processTrees()

	var out []*Container
	for _, ct := range list.Items {
		res, err := c.ContainerInspect(ctx, ct.ID, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		insp := res.Container
		name := strings.TrimPrefix(insp.Name, "/")
		if name == "" {
			continue
		}
		if insp.State == nil || !insp.State.Running {
			continue
		}
		pid := uint32(insp.State.Pid)
		image := ""
		if insp.Config != nil {
			image = insp.Config.Image
		}
		logPath := ""
		if insp.LogPath != "" && insp.HostConfig != nil && insp.HostConfig.LogConfig.Type == "json-file" {
			logPath = insp.LogPath
		}
		dc := &Container{
			ID:      containerID(KindDocker, name),
			Name:    name,
			Image:   image,
			Kind:    KindDocker,
			PID:     pid,
			logPath: logPath,
			hyperv:  insp.HostConfig != nil && insp.HostConfig.Isolation == "hyperv",
		}
		if insp.State.StartedAt != "" {
			if t, err := time.Parse(time.RFC3339Nano, insp.State.StartedAt); err == nil {
				dc.StartedAt = t
			}
		}
		if pid != 0 {
			dc.PIDs = trees[pid]
		}
		if insp.NetworkSettings != nil {
			for _, n := range insp.NetworkSettings.Networks {
				if n == nil {
					continue
				}
				for _, ip := range []netip.Addr{n.IPAddress, n.GlobalIPv6Address} {
					if ip.IsValid() && usableContainerIP(ip) {
						dc.ips = append(dc.ips, ip)
					}
				}
			}
			seen := map[netip.AddrPort]bool{}
			for port, bindings := range insp.NetworkSettings.Ports {
				if port.Proto() != network.TCP {
					continue
				}
				for _, b := range bindings {
					ap, err := netip.ParseAddrPort(net.JoinHostPort(b.HostIP.String(), b.HostPort))
					if err != nil || common.PortFilter.ShouldBeSkipped(ap.Port()) {
						continue
					}
					if !seen[ap] {
						seen[ap] = true
						dc.hostListens = append(dc.hostListens, ap)
					}
				}
			}
		}
		out = append(out, dc)
	}
	return out
}

func (d *dockerClient) stats(name string) (*Stats, error) {
	c := d.ensure()
	if c == nil {
		return nil, errDockerUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	resp, err := c.ContainerStats(ctx, name, client.ContainerStatsOptions{})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var s container.StatsResponse
	if err = json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}

	mem := s.MemoryStats.PrivateWorkingSet
	if mem == 0 {
		mem = s.MemoryStats.Usage
	}
	return &Stats{
		CPUSeconds:     float64(s.CPUStats.CPUUsage.TotalUsage) / 1e7,
		MemoryRSSBytes: mem,
	}, nil
}
