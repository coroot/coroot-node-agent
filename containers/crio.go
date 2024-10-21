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
	"k8s.io/klog/v2"
)

const crioTimeout = 30 * time.Second

var (
	crioClient *http.Client
)

type CrioContainerInfo struct {
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	Labels          map[string]string `json:"labels"`
	LogPath         string            `json:"log_path"`
	CrioAnnotations map[string]string `json:"crio_annotations"`
}

type CrioVolume struct {
	ContainerPath string `json:"container_path"`
	HostPath      string `json:"host_path"`
}

func CrioInit() error {
	sockets := []string{
		"/var/run/crio/crio.sock",
		"/run/crio/crio.sock",
	}
	var crioSocket string
	var err error
	for _, socket := range sockets {
		socketHostPath := proc.HostPath(socket)
		if _, err := os.Stat(socketHostPath); err == nil {
			crioSocket = socketHostPath
			break
		}
	}
	if err != nil {
		return fmt.Errorf("couldn't connect to CRI-O through the following UNIX sockets: [%s]: %s",
			strings.Join(sockets, ","), err,
		)
	}
	klog.Infoln("cri-o socket:", crioSocket)

	crioClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("unix", crioSocket, crioTimeout)
			},
			DisableCompression: true,
		},
	}

	return nil
}

func CrioInspect(containerID string) (*ContainerMetadata, error) {
	if crioClient == nil {
		return nil, fmt.Errorf("cri-o client is not initialized")
	}
	resp, err := crioClient.Get("http://localhost/containers/" + containerID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	i := &CrioContainerInfo{}
	if err = json.NewDecoder(resp.Body).Decode(i); err != nil {
		return nil, err
	}

	res := &ContainerMetadata{
		name:       i.Name,
		labels:     i.Labels,
		volumes:    map[string]string{},
		logPath:    i.LogPath,
		image:      i.Image,
		logDecoder: logparser.CriDecoder{},
	}

	var volumes []CrioVolume

	if err := json.Unmarshal([]byte(i.CrioAnnotations["io.kubernetes.cri-o.Volumes"]), &volumes); err != nil {
		klog.Warningln(err)
	} else {
		for _, v := range volumes {
			res.volumes[v.ContainerPath] = common.ParseKubernetesVolumeSource(v.HostPath)
		}
	}
	return res, nil
}
