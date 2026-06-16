//go:build windows

package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
	"k8s.io/klog/v2"
)

func uname() (string, string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", "", err
	}
	return hostname, "10.0.0", nil
}

func machineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		klog.Warningln("failed to open MachineGuid registry key:", err)
		return fallbackMachineID()
	}
	defer k.Close()

	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		klog.Warningln("failed to read MachineGuid:", err)
		return fallbackMachineID()
	}
	id := strings.TrimSpace(strings.Replace(guid, "-", "", -1))
	klog.Infoln("machine-id: ", id)
	return id
}

func fallbackMachineID() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(hostname)
}

func systemUUID() string {
	return ""
}

func checkKernelVersion() {}
