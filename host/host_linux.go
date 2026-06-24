//go:build linux

package host

import (
	"os"
	"strings"

	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

func MachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/devices/virtual/dmi/id/product_uuid"} {
		payload, err := os.ReadFile(proc.HostPath(p))
		if err != nil {
			klog.Warningln("failed to read machine-id:", err)
			continue
		}
		id := strings.TrimSpace(strings.ReplaceAll(string(payload), "-", ""))
		klog.Infoln("machine-id:", id)
		return id
	}
	return ""
}

func SystemUUID() string {
	payload, err := os.ReadFile(proc.HostPath("/sys/devices/virtual/dmi/id/product_uuid"))
	if err != nil {
		klog.Warningln("failed to read system-uuid:", err)
		return ""
	}
	return strings.TrimSpace(string(payload))
}
