package containers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"inet.af/netaddr"
)

const dockerdTimeout = 30 * time.Second

var (
	dockerdClient *client.Client
)

func DockerdInit() error {
	c, err := client.New(
		client.WithHost("unix://" + proc.HostPath("/run/docker.sock")),
	)
	if err != nil {
		return err
	}
	ctx, cancelFn := context.WithTimeout(context.Background(), dockerdTimeout)
	defer cancelFn()
	if _, err := c.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		return err
	}
	dockerdClient = c
	return nil
}

func DockerdInspect(containerID string) (*ContainerMetadata, error) {
	if dockerdClient == nil {
		return nil, fmt.Errorf("dockerd client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerdTimeout)
	defer cancel()
	insp, err := dockerdClient.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return nil, err
	}
	c := insp.Container
	res := &ContainerMetadata{
		name:        strings.TrimPrefix(c.Name, "/"),
		labels:      c.Config.Labels,
		image:       c.Config.Image,
		volumes:     map[string]string{},
		hostListens: map[string][]netaddr.IPPort{},
		networks:    map[string]ContainerNetwork{},
		env:         map[string]string{},
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
			if port.Proto() != network.TCP {
				continue
			}
			for _, b := range bindings {
				if ipp, err := netaddr.ParseIPPort(b.HostIP.String() + ":" + b.HostPort); err == nil {
					addrs[ipp] = struct{}{}
				}
			}
		}
		if len(addrs) > 0 {
			s := make([]netaddr.IPPort, 0, len(addrs))
			for addr := range addrs {
				if common.PortFilter.ShouldBeSkipped(addr.Port()) {
					continue
				}
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
	if c.Config != nil {
		for _, value := range c.Config.Env {
			idx := strings.Index(value, "=")
			if idx < 0 {
				continue
			}
			k := value[:idx]
			v := value[idx+1:]
			res.env[k] = v
		}
	}
	return res, nil
}
