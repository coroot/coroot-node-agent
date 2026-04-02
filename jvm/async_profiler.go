package jvm

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

const (
	apDeployDir = "/tmp/coroot"
	apLibName   = "libasyncProfiler.so"
)

func apAssetName() string {
	if runtime.GOARCH == "amd64" {
		return "libasyncProfiler_amd64.so"
	}
	return "libasyncProfiler_arm64.so"
}

func apContainerLibPath() string {
	return filepath.Join(apDeployDir, apLibName)
}

func apContainerDumpPath(nsPid uint32) string {
	return filepath.Join(apDeployDir, fmt.Sprintf("ap_%d.jfr", nsPid))
}

func apHostDumpPath(pid, nsPid uint32) string {
	return proc.Path(pid, "root", apContainerDumpPath(nsPid))
}

func apCommand(pid uint32, args string) error {
	return LoadNativeAgent(pid, apContainerLibPath(), args)
}

func apStartArgs(nsPid uint32) string {
	return fmt.Sprintf("start,event=itimer,interval=10ms,alloc,lock,jfr,file=%s", apContainerDumpPath(nsPid))
}

func IsAsyncProfilerAlreadyLoaded(pid uint32) bool {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, apDeployDir) {
			continue
		}
		if strings.Contains(line, "libasyncProfiler") {
			return true
		}
	}
	return false
}

func DeployAndStartAsyncProfiler(pid uint32) error {
	if err := os.MkdirAll(proc.Path(pid, "root", apDeployDir), 0755); err != nil {
		return fmt.Errorf("failed to create deploy dir: %w", err)
	}
	libData, err := agentAssets.ReadFile("assets/" + apAssetName())
	if err != nil {
		return fmt.Errorf("failed to read embedded async-profiler lib: %w", err)
	}
	libDest := proc.Path(pid, "root", apContainerLibPath())
	if err := writeFileIfChanged(libDest, libData); err != nil {
		return fmt.Errorf("failed to deploy async-profiler lib: %w", err)
	}

	nsPid, err := proc.GetNsPid(pid)
	if err != nil {
		return err
	}

	apCommand(pid, "stop")
	if err := apCommand(pid, apStartArgs(nsPid)); err != nil {
		return err
	}
	klog.Infof("pid=%d: async-profiler started (itimer+alloc+lock)", pid)
	return nil
}

func CollectAsyncProfiler(pid uint32) ([]byte, error) {
	nsPid, err := proc.GetNsPid(pid)
	if err != nil {
		return nil, err
	}
	hostPath := apHostDumpPath(pid, nsPid)

	if err := apCommand(pid, "stop"); err != nil {
		return nil, fmt.Errorf("asprof stop failed for JVM %d: %w", pid, err)
	}

	data, err := os.ReadFile(hostPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read async-profiler dump %s: %w", hostPath, err)
	}
	os.Remove(hostPath)

	if err := apCommand(pid, apStartArgs(nsPid)); err != nil {
		klog.Warningf("pid=%d: failed to restart async-profiler: %v", pid, err)
	}

	return data, nil
}

func StopAsyncProfiler(pid uint32) {
	apCommand(pid, "stop")
}
