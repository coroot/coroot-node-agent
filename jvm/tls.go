package jvm

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

const (
	deployDir     = "/tmp/coroot"
	nativeLibName = "libcoroot_java_tls.so"
	agentJarName  = "coroot-java-tls-agent.jar"
)

//go:embed assets/*
var agentAssets embed.FS

func nativeLibAssetName() string {
	if runtime.GOARCH == "amd64" {
		return "libcoroot_java_tls_amd64.so"
	}
	return "libcoroot_java_tls_arm64.so"
}

func deployAndLoadTlsAgent(pid uint32) (nativeLibPath string, err error) {
	rootPath := proc.Path(pid, "root")
	containerDeployDir := filepath.Join(rootPath, deployDir)
	if err = os.MkdirAll(containerDeployDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create deploy dir: %w", err)
	}
	nativeLibData, err := agentAssets.ReadFile("assets/" + nativeLibAssetName())
	if err != nil {
		return "", fmt.Errorf("failed to read embedded native lib: %w", err)
	}
	nativeLibDest := filepath.Join(containerDeployDir, nativeLibName)
	if err = writeFileIfChanged(nativeLibDest, nativeLibData); err != nil {
		return "", fmt.Errorf("failed to deploy native lib: %w", err)
	}
	agentJarData, err := agentAssets.ReadFile("assets/" + agentJarName)
	if err != nil {
		return "", fmt.Errorf("failed to read embedded agent jar: %w", err)
	}
	agentJarDest := filepath.Join(containerDeployDir, agentJarName)
	if err = writeFileIfChanged(agentJarDest, agentJarData); err != nil {
		return "", fmt.Errorf("failed to deploy agent jar: %w", err)
	}
	containerAgentPath := filepath.Join(deployDir, agentJarName)
	containerNativeLibPath := filepath.Join(deployDir, nativeLibName)

	if err = LoadAgent(pid, containerAgentPath, containerNativeLibPath); err != nil {
		return "", fmt.Errorf("failed to load agent into JVM %d: %w", pid, err)
	}
	klog.Infof("pid=%d: Java TLS agent loaded successfully", pid)
	return nativeLibDest, nil
}

func EnsureTlsAgentLoaded(pid uint32) string {
	if !canLoadJavaAgent(pid) {
		return ""
	}
	if p := getLoadedNativeLibPath(pid); p != "" {
		return p
	}
	p, err := deployAndLoadTlsAgent(pid)
	if err != nil {
		klog.Warningln(err)
	}
	return p
}

func getLoadedNativeLibPath(pid uint32) string {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) <= 5 {
			continue
		}
		libPath := parts[5]
		if strings.Contains(libPath, "libcoroot_java_tls.so") {
			fullPath := proc.Path(pid, "root", libPath)
			if _, err = os.Stat(fullPath); err == nil {
				return fullPath
			}
		}
	}
	return ""
}

func IsJavaProcess(pid uint32) bool {
	cmdline := proc.GetCmdline(pid)
	if len(cmdline) == 0 {
		return false
	}
	parts := bytes.Split(cmdline, []byte{0})
	if len(parts) == 0 {
		return false
	}
	cmd := parts[0]
	return bytes.HasSuffix(cmd, []byte("java"))
}

func canLoadJavaAgent(pid uint32) bool {
	cmdline := proc.GetCmdline(pid)
	if bytes.Contains(cmdline, []byte("-XX:+DisableAttachMechanism")) {
		klog.Infof("pid=%d: skipping Java TLS agent: attach mechanism disabled", pid)
		return false
	}
	if bytes.Contains(cmdline, []byte("-XX:-EnableDynamicAgentLoading")) {
		klog.Infof("pid=%d: skipping Java TLS agent: dynamic agent loading disabled", pid)
		return false
	}
	if !IsHotSpotJVM(pid) {
		klog.Infof("pid=%d: skipping Java TLS agent: unsupported JVM (only HotSpot-based JVMs are supported)", pid)
		return false
	}
	return true
}

func IsHotSpotJVM(pid uint32) bool {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	hasLibjvm := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "libj9vm") {
			return false // OpenJ9
		}
		if strings.Contains(line, "libjvm.so") {
			hasLibjvm = true
		}
	}
	return hasLibjvm
}

func writeFileIfChanged(path string, data []byte) error {
	existing, err := os.ReadFile(path)
	if err == nil && len(existing) == len(data) {
		return nil
	}
	return os.WriteFile(path, data, 0755)
}
