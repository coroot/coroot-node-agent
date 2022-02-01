package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/pkg/cri/constants"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
	"k8s.io/klog/v2"
	"time"
)

const containerdTimeout = 30 * time.Second

var (
	containerdClient *containerd.Client
)

func ContainerdInit() error {
	c, err := containerd.New(proc.HostPath("/run/containerd/containerd.sock"),
		containerd.WithDefaultNamespace(constants.K8sContainerdNamespace),
		containerd.WithTimeout(time.Second))
	if err != nil {
		return err
	}
	containerdClient = c
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
		volumes: map[string]Volume{},
	}

	var spec oci.Spec
	if err := json.Unmarshal(c.Spec.Value, &spec); err != nil {
		klog.Warningln(err)
	} else {
		for _, m := range spec.Mounts {
			if provisioner, volume := parseVolumeSource(m.Source); provisioner != "" && volume != "" {
				res.volumes[m.Destination] = Volume{provisioner: provisioner, volume: volume}
			}
		}
	}

	if data, ok := c.Extensions["io.cri-containerd.container.metadata"]; ok {
		var md = struct { // from data.TypeUrl
			Metadata struct {
				LogPath string
			}
		}{}
		if err := json.Unmarshal(data.Value, &md); err != nil {
			klog.Warningln(err)
		} else {
			res.logPath = md.Metadata.LogPath
			res.logDecoder = logparser.CriDecoder{}
		}
	}

	return res, nil
}
