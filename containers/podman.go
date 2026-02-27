package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const podmanTimeout = 30 * time.Second

var podmanClient *http.Client

func PodmanInit() error {
	sockets := []string{
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock",
	}
	var podmanSocket string
	for _, socket := range sockets {
		socketHostPath := proc.HostPath(socket)
		if _, err := os.Stat(socketHostPath); err == nil {
			podmanSocket = socketHostPath
			break
		}
	}
	if podmanSocket == "" {
		return fmt.Errorf("podman socket not found in [%s]", strings.Join(sockets, ","))
	}
	klog.Infoln("podman socket:", podmanSocket)

	podmanClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("unix", podmanSocket, podmanTimeout)
			},
			DisableCompression: true,
		},
	}
	return nil
}

type podmanContainerInfo struct {
	Name   string `json:"Name"`
	Image  string `json:"ImageName"`
	Config struct {
		Labels map[string]string `json:"Labels"`
		Env    []string          `json:"Env"`
	} `json:"Config"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	HostConfig struct {
		LogConfig struct {
			Type string `json:"Type"`
		} `json:"LogConfig"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	LogPath string `json:"LogPath"`
}

func PodmanInspect(containerID string) (*ContainerMetadata, error) {
	if podmanClient == nil {
		return nil, fmt.Errorf("podman client not initialized")
	}
	resp, err := podmanClient.Get("http://localhost/v4.0.0/libpod/containers/" + containerID + "/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	i := &podmanContainerInfo{}
	if err = json.NewDecoder(resp.Body).Decode(i); err != nil {
		return nil, err
	}

	res := &ContainerMetadata{
		name:        strings.TrimPrefix(i.Name, "/"),
		image:       i.Image,
		labels:      i.Config.Labels,
		volumes:     map[string]string{},
		hostListens: map[string][]netaddr.IPPort{},
		networks:    map[string]ContainerNetwork{},
		env:         map[string]string{},
	}
	if res.labels == nil {
		res.labels = map[string]string{}
	}

	for _, m := range i.Mounts {
		res.volumes[m.Destination] = common.ParseKubernetesVolumeSource(m.Source)
	}

	for _, value := range i.Config.Env {
		idx := strings.Index(value, "=")
		if idx < 0 {
			continue
		}
		res.env[value[:idx]] = value[idx+1:]
	}

	if i.NetworkSettings.Ports != nil {
		addrs := map[netaddr.IPPort]struct{}{}
		for port, bindings := range i.NetworkSettings.Ports {
			if !strings.HasSuffix(port, "/tcp") {
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
				if common.PortFilter.ShouldBeSkipped(addr.Port()) {
					continue
				}
				s = append(s, addr)
			}
			res.hostListens["podman"] = s
		}
	}

	switch i.HostConfig.LogConfig.Type {
	case "json-file", "k8s-file":
		if i.LogPath != "" {
			res.logPath = i.LogPath
			res.logDecoder = logparser.DockerJsonDecoder{}
		}
	default:
		// journald is the Podman default log driver.
		// Store the unit name so runLogParser can subscribe via journald.
		res.podmanJournaldUnit = "libpod-" + containerID + ".scope"
	}

	return res, nil
}
