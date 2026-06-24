//go:build windows

package host

import (
	"strings"

	"github.com/siderolabs/go-smbios/smbios"
	"golang.org/x/sys/windows/registry"
	"k8s.io/klog/v2"
)

func MachineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		klog.Warningln("failed to open registry key for MachineGuid:", err)
		return ""
	}
	defer k.Close()

	val, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		klog.Warningln("failed to read MachineGuid:", err)
		return ""
	}
	id := strings.TrimSpace(strings.ReplaceAll(val, "-", ""))
	klog.Infoln("machine-id:", id)
	return id
}

func SystemUUID() string {
	s, err := smbios.New()
	if err != nil {
		klog.Warningln("failed to read SMBIOS:", err)
		return ""
	}
	uuid := strings.ToUpper(s.SystemInformation.UUID)
	if uuid != "" {
		klog.Infoln("system-uuid:", uuid)
	}
	return uuid
}
