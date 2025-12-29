package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const podmanTimeout = 30 * time.Second

var (
	podmanClient *PodmanClient
)

// PodmanClient represents a client for interacting with Podman API
type PodmanClient struct {
	socketPath string
}

// runCmd runs a command with a timeout and returns its output
func runCmd(command string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("command failed: %w, output: %s", err, string(output))
	}
	return string(output), nil
}

// isPodmanAvailable checks if the podman command is available
func isPodmanAvailable() bool {
	_, err := exec.LookPath("podman")
	return err == nil
}

// PodmanInit initializes the Podman client
func PodmanInit() error {
	klog.Infof("Initializing Podman support")
	
	// Try common Podman socket paths
	sockets := []string{
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock",
		proc.HostPath("/run/podman/podman.sock"),
		proc.HostPath("/var/run/podman/podman.sock"),
	}

	for _, socket := range sockets {
		// Check if the socket exists and is accessible
		if _, err := os.Stat(socket); err == nil {
			klog.Infof("Found Podman socket at %s", socket)
			podmanClient = &PodmanClient{
				socketPath: socket,
			}
			break
		} else {
			klog.V(5).Infof("Podman socket not found at %s: %v", socket, err)
		}
	}

	// If no socket was found, that's okay - we'll try other approaches
	if podmanClient == nil {
		klog.Infof("No Podman socket found, will use CLI-based inspection")
	} else {
		klog.Infof("Using Podman socket at %s", podmanClient.socketPath)
	}
	
	return nil
}

// readContainerConfigFromFile reads container configuration from filesystem
func readContainerConfigFromFile(containerID string) (*ContainerMetadata, error) {
	// Try to read container config from the standard Podman location
	configPath := filepath.Join("/var/lib/containers/storage/overlay-containers", containerID, "userdata", "config.json")
	configPath = proc.HostPath(configPath)
	
	if _, err := os.Stat(configPath); err != nil {
		return nil, fmt.Errorf("config file not found: %w", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the container configuration
	var config struct {
		ID      string            `json:"id"`
		Name    string            `json:"name"`
		Image   string            `json:"rootfsImageName"`
		Config  struct {
			Labels map[string]string `json:"Labels"`
			Env    []string          `json:"Env"`
		} `json:"config"`
		Mounts []struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
		} `json:"mounts"`
		NetworkSettings struct {
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"ports"`
		} `json:"networkSettings"`
	}
	
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse container config: %w", err)
	}

	res := &ContainerMetadata{
		name:        strings.TrimPrefix(config.Name, "/"),
		labels:      config.Config.Labels,
		image:       config.Image,
		volumes:     map[string]string{},
		hostListens: map[string][]netaddr.IPPort{},
		networks:    map[string]ContainerNetwork{},
		env:         map[string]string{},
	}

	// Parse volumes
	for _, mount := range config.Mounts {
		res.volumes[mount.Destination] = common.ParseKubernetesVolumeSource(mount.Source)
	}

	// Parse environment variables
	for _, envVar := range config.Config.Env {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			res.env[parts[0]] = parts[1]
		}
	}

	// Parse network settings
	for port, bindings := range config.NetworkSettings.Ports {
		if len(bindings) > 0 {
			ipport, err := netaddr.ParseIPPort(bindings[0].HostIP + ":" + bindings[0].HostPort)
			if err != nil {
				continue
			}
			res.hostListens[port] = append(res.hostListens[port], ipport)
		}
	}

	// Try to find log file
	logPath := filepath.Join("/var/lib/containers/storage/overlay-containers", containerID, "userdata", "ctr.log")
	logPath = proc.HostPath(logPath)
	if _, err := os.Stat(logPath); err == nil {
		res.logPath = logPath
		res.logDecoder = logparser.DockerJsonDecoder{} // Podman uses same log format as Docker
	}

	return res, nil
}

// PodmanInspect inspects a container using multiple approaches
func PodmanInspect(containerID string) (*ContainerMetadata, error) {
	klog.Infof("Inspecting Podman container %s", containerID)
	
	// First, try to read from filesystem directly
	if md, err := readContainerConfigFromFile(containerID); err == nil {
		klog.Infof("Successfully read container metadata from filesystem for %s", containerID)
		return md, nil
	} else {
		klog.V(5).Infof("Failed to read container metadata from filesystem for %s: %v", containerID, err)
	}

	// If filesystem read fails, try using podman command if available
	if isPodmanAvailable() {
		klog.Infof("Trying to get container metadata using podman command for %s", containerID)
		// Run podman inspect command
		cmd := fmt.Sprintf("podman inspect %s", containerID)
		output, err := runCmd(cmd, podmanTimeout)
		if err != nil {
			klog.Warningf("Failed to run podman inspect for %s: %v", containerID, err)
			return nil, fmt.Errorf("failed to run podman inspect: %w", err)
		}

		// Parse the JSON output
		var containers []struct {
			ID      string            `json:"Id"`
			Name    string            `json:"Name"`
			Image   string            `json:"Image"`
			Config  struct {
				Labels map[string]string `json:"Labels"`
				Env    []string          `json:"Env"`
			} `json:"Config"`
			Mounts []struct {
				Source      string `json:"Source"`
				Destination string `json:"Destination"`
			} `json:"Mounts"`
			NetworkSettings struct {
				Ports map[string][]struct {
					HostIP   string `json:"HostIp"`
					HostPort string `json:"HostPort"`
				} `json:"Ports"`
			} `json:"NetworkSettings"`
		}
		
		if err := json.Unmarshal([]byte(output), &containers); err != nil {
			klog.Warningf("Failed to parse podman inspect output for %s: %v", containerID, err)
			return nil, fmt.Errorf("failed to parse podman inspect output: %w", err)
		}
		
		if len(containers) == 0 {
			klog.Warningf("No container found with ID %s", containerID)
			return nil, fmt.Errorf("no container found with ID %s", containerID)
		}
		
		container := containers[0]
		klog.Infof("Successfully inspected container %s with name %s", container.ID, container.Name)

		res := &ContainerMetadata{
			name:        strings.TrimPrefix(container.Name, "/"),
			labels:      container.Config.Labels,
			image:       container.Image,
			volumes:     map[string]string{},
			hostListens: map[string][]netaddr.IPPort{},
			networks:    map[string]ContainerNetwork{},
			env:         map[string]string{},
		}

		// Parse volumes
		for _, mount := range container.Mounts {
			res.volumes[mount.Destination] = common.ParseKubernetesVolumeSource(mount.Source)
		}

		// Parse environment variables
		for _, envVar := range container.Config.Env {
			parts := strings.SplitN(envVar, "=", 2)
			if len(parts) == 2 {
				res.env[parts[0]] = parts[1]
			}
		}

		// Parse network settings
		for port, bindings := range container.NetworkSettings.Ports {
			if len(bindings) > 0 {
				ipport, err := netaddr.ParseIPPort(bindings[0].HostIP + ":" + bindings[0].HostPort)
				if err != nil {
					continue
				}
				res.hostListens[port] = append(res.hostListens[port], ipport)
			}
		}

		// Try to find log file
		logPath := fmt.Sprintf("/var/lib/containers/storage/overlay-containers/%s/userdata/ctr.log", containerID)
		logPath = proc.HostPath(logPath)
		if _, err := os.Stat(logPath); err == nil {
			res.logPath = logPath
			res.logDecoder = logparser.DockerJsonDecoder{} // Podman uses same log format as Docker
		}

		return res, nil
	}

	// If both approaches fail, return minimal metadata
	klog.Warningf("Unable to get detailed metadata for Podman container %s, returning minimal metadata", containerID)
	return &ContainerMetadata{
		name:   fmt.Sprintf("libpod-%s", containerID[:12]),
		image:  "unknown",
		labels: map[string]string{},
		volumes: map[string]string{},
		env: map[string]string{},
	}, nil
}