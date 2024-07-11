package ebpftracer

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

var (
	libcRegexp = regexp.MustCompile(`libc[\.-]`)
	muslRegexp = regexp.MustCompile(`musl[\.-]`)
)

func (t *Tracer) AttachPythonThreadLockProbes(pid uint32) []link.Link {
	exePath := getPthreadLib(pid)
	if exePath == "" {
		return nil
	}

	log := func(msg string, err error) {
		if err != nil {
			for _, s := range []string{"no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					return
				}
			}
			klog.ErrorfDepth(1, "pid=%d lib=%s: %s: %s", pid, exePath, msg, err)
			return
		}
		klog.InfofDepth(1, "pid=%d lib=%s: %s", pid, exePath, msg)
	}
	exe, err := link.OpenExecutable(exePath)
	if err != nil {
		log("failed to open executable", err)
		return nil
	}
	var links []link.Link
	uprobe, err := exe.Uprobe("pthread_cond_timedwait", t.uprobes["pthread_cond_timedwait_enter"], nil)
	if err != nil {
		log("failed to attach uprobe", err)
		return nil
	}
	links = append(links, uprobe)
	uretprobe, err := exe.Uretprobe("pthread_cond_timedwait", t.uprobes["pthread_cond_timedwait_exit"], nil)
	if err != nil {
		log("failed to attach uretprobe", err)
		return nil
	}
	links = append(links, uretprobe)
	log("python uprobes attached", nil)
	return links
}

func getPthreadLib(pid uint32) string {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	libc := ""
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) <= 5 {
			continue
		}
		libPath := parts[5]
		switch {
		case libcRegexp.MatchString(libPath):
			libc = proc.Path(pid, "root", libPath)
		case muslRegexp.MatchString(libPath):
			return proc.Path(pid, "root", libPath)
		case strings.Contains(libPath, "libpthread"):
			return proc.Path(pid, "root", libPath)
		}
	}
	return libc
}
