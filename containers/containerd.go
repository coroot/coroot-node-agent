package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/pkg/cri/constants"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
	"k8s.io/klog/v2"
)

const containerdTimeout = 30 * time.Second

var (
	containerdClient *containerd.Client
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
		containerdClient, err = containerd.New(proc.HostPath(socket),
			containerd.WithDefaultNamespace(constants.K8sContainerdNamespace),
			containerd.WithTimeout(time.Second))
		if err == nil {
			klog.Infoln("using", socket)
			break
		}
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
