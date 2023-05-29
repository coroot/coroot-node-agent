package containers

import (
	"context"
	"fmt"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
	"github.com/docker/docker/client"
	"github.com/vishvananda/netns"
	"inet.af/netaddr"
	"os"
	"path"
	"strings"
	"time"
)

const dockerdTimeout = 30 * time.Second

var (
	dockerdClient *client.Client
)

func DockerdInit() error {
	c, err := client.NewClientWithOpts(
		client.WithHost("unix://" + proc.HostPath("/run/docker.sock")),
	)
	if err != nil {
		return err
	}
	ctx, cancelFn := context.WithTimeout(context.Background(), dockerdTimeout)
	defer cancelFn()
	if _, err := c.Ping(ctx); err != nil {
		return err
	}
	c.NegotiateAPIVersion(ctx)
	dockerdClient = c
	return nil
}

func DockerdInspect(containerID string) (*ContainerMetadata, error) {
	if dockerdClient == nil {
		return nil, fmt.Errorf("dockerd client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerdTimeout)
	defer cancel()
	c, err := dockerdClient.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, err
	}
	res := &ContainerMetadata{
		name:        strings.TrimPrefix(c.Name, "/"),
		labels:      c.Config.Labels,
		image:       c.Config.Image,
		volumes:     map[string]string{},
		hostListens: map[string][]netaddr.IPPort{},
		networks:    map[string]ContainerNetwork{},
	}
	for _, m := range c.Mounts {
		res.volumes[m.Destination] = common.ParseKubernetesVolumeSource(m.Source)
	}
	if c.LogPath != "" && c.HostConfig.LogConfig.Type == "json-file" {
		res.logPath = c.LogPath
		res.logDecoder = logparser.DockerJsonDecoder{}
	}
	if c.NetworkSettings != nil {
		addrs := map[netaddr.IPPort]struct{}{}
		for port, bindings := range c.NetworkSettings.Ports {
			if port.Proto() != "tcp" {
				continue
			}
			for _, b := range bindings {
				if ipp, err := netaddr.ParseIPPort(b.HostIP + ":" + b.HostPort); err == nil {
					addrs[ipp] = struct{}{}
				}
			}
		}
		if len(addrs) > 0 {
			s := make([]netaddr.IPPort, 0, len(addrs))
			for addr := range addrs {
				s = append(s, addr)
			}
			res.hostListens["dockerd"] = s
		}
		for name, network := range c.NetworkSettings.Networks {
			res.networks[name] = ContainerNetwork{
				NetworkID: network.NetworkID,
			}
		}
	}
	return res, nil
}

func FindNetworkLoadBalancerNs(networkId string) netns.NsHandle {
	basePath := "/run/docker/netns"
	files, err := os.ReadDir(proc.HostPath(basePath))
	if err != nil {
		return -1
	}
	for _, f := range files {
		if !f.Type().IsRegular() || !strings.HasPrefix(f.Name(), "lb_") {
			continue
		}
		idPrefix := strings.Split(f.Name(), "_")[1]
		if strings.HasPrefix(networkId, idPrefix) {
			ns, _ := netns.GetFromPath(proc.HostPath(path.Join(basePath, f.Name())))
			return ns
		}
	}
	return -1
}
