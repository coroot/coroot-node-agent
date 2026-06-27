//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"k8s.io/klog/v2"
)

const windowsServiceName = "coroot-node-agent"

func runPlatform() error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if isService {
		return svc.Run(windowsServiceName, newWindowsService(runAgent))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAgent(ctx)
}

func uname() (string, string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", "", err
	}
	version := windows.RtlGetVersion()
	return hostname, fmt.Sprintf("%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber), nil
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

func setKernelVersion(string) error {
	return nil
}

func nodeInfoKernelVersion(version string) string {
	if strings.HasPrefix(strings.ToLower(version), "windows") {
		return version
	}
	return "Windows " + version
}

func checkKernelVersion() {}
