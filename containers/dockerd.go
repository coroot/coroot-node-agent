package containers

import (
	"context"
	"fmt"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
	"github.com/docker/docker/client"
	"inet.af/netaddr"
	"strings"
	"time"
)

const dockerdTimeout = 30 * time.Second

var (
	dockerdClient *client.Client
)

func DockerdInit() error {
	c, err := client.NewClientWithOpts(
		client.WithHost("unix://"+proc.HostPath("/run/docker.sock")),
		client.WithVersion("1.12"),
	)
	if err != nil {
		return err
	}
	ctx, cancelFn := context.WithTimeout(context.Background(), dockerdTimeout)
	defer cancelFn()
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
		volumes:     map[string]Volume{},
		hostListens: map[string][]netaddr.IPPort{},
	}
	for _, m := range c.Mounts {
		if provisioner, volume := parseVolumeSource(m.Source); provisioner != "" && volume != "" {
			res.volumes[m.Destination] = Volume{provisioner: provisioner, volume: volume}
		}
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
	}
	return res, nil
}
