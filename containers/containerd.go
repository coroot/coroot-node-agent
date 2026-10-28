package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
	"k8s.io/klog/v2"
)

const (
	containerdTimeout      = 30 * time.Second
	k8sContainerdNamespace = "k8s.io"
)

var (
	containerdClient *client.Client
)

func ContainerdInit() error {
	sockets := []string{
		"/var/snap/microk8s/common/run/containerd.sock",
		"/run/k0s/containerd.sock",
		"/run/k3s/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
	}
	var err error
	for _, socket := range sockets {
		var c *client.Client
		c, err = client.New(proc.HostPath(socket),
			client.WithDefaultNamespace(k8sContainerdNamespace),
			client.WithTimeout(time.Second))
		if err != nil {
			continue
		}
		// the client connects lazily, so make sure this socket is actually served before using it
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		serving, serveErr := c.IsServing(ctx)
		cancel()
		if serveErr != nil || !serving {
			_ = c.Close()
			err = fmt.Errorf("%s: not serving: %v", socket, serveErr)
			continue
		}
		containerdClient = c
		klog.Infoln("using", socket)
		break
	}
	if containerdClient == nil {
		return fmt.Errorf(
			"couldn't connect to containerd through the following UNIX sockets [%s]: %s",
			strings.Join(sockets, ","), err,
		)
	}
	return nil
}

func ContainerdInspect(containerID string) (*ContainerMetadata, error) {
	if containerdClient == nil {
		return nil, fmt.Errorf("containerd client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), containerdTimeout)
	defer cancel()

	c, err := containerdClient.ContainerService().Get(ctx, containerID)
	if err != nil {
		return nil, err
	}

	res := &ContainerMetadata{
		labels:  c.Labels,
		image:   c.Image,
		volumes: map[string]string{},
	}

	var spec oci.Spec
	if err := json.Unmarshal(c.Spec.GetValue(), &spec); err != nil {
		klog.Warningln(err)
	} else {
		for _, m := range spec.Mounts {
			res.volumes[m.Destination] = common.ParseKubernetesVolumeSource(m.Source)
		}
	}

	if data, ok := c.Extensions["io.cri-containerd.container.metadata"]; ok {
		var md = struct { // from data.TypeUrl
			Metadata struct {
				LogPath string
			}
		}{}
		if err := json.Unmarshal(data.GetValue(), &md); err != nil {
			klog.Warningln(err)
		} else {
			res.logPath = md.Metadata.LogPath
			res.logDecoder = logparser.CriDecoder{}
		}
	}

	return res, nil
}
