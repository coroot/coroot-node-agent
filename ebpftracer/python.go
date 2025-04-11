package ebpftracer

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/proc"
	"golang.org/x/exp/maps"
	"k8s.io/klog/v2"
)

var (
	libcRegexp = regexp.MustCompile(`libc[\.-]`)
	muslRegexp = regexp.MustCompile(`musl[\.-]`)
)

func (t *Tracer) AttachPythonThreadLockProbes(pid uint32) []link.Link {
	log := func(libPath, msg string, err error) {
		if err != nil {
			for _, s := range []string{"no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					return
				}
			}
			klog.ErrorfDepth(1, "pid=%d lib=%s: %s: %s", pid, libPath, msg, err)
			return
		}
		klog.InfofDepth(1, "pid=%d lib=%s: %s", pid, libPath, msg)
	}

	var (
		lastErr error
		links   []link.Link
		libPath string
	)

	for _, libPath = range getPthreadLibs(pid) {
		exe, err := link.OpenExecutable(libPath)
		if err != nil {
			log(libPath, "failed to open executable", err)
			return nil
		}
		options := &link.UprobeOptions{PID: int(pid)}
		var uprobe, uretprobe link.Link
		uprobe, lastErr = exe.Uprobe("pthread_cond_timedwait", t.uprobes["pthread_cond_timedwait_enter"], options)
		if lastErr != nil {
			continue
		}
		links = append(links, uprobe)
		uretprobe, lastErr = exe.Uretprobe("pthread_cond_timedwait", t.uprobes["pthread_cond_timedwait_exit"], options)
		if lastErr != nil {
			continue
		}
		links = append(links, uretprobe)
		log(libPath, "python uprobes attached", nil)
		break
	}
	if lastErr != nil {
		log(libPath, "failed to attach uprobe", lastErr)
	}
	return links
}

func getPthreadLibs(pid uint32) []string {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	libs := map[string]bool{}
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) <= 5 {
			continue
		}
		libPath := parts[5]
		if libcRegexp.MatchString(libPath) || muslRegexp.MatchString(libPath) || strings.Contains(libPath, "libpthread") {
			libs[proc.Path(pid, "root", libPath)] = true
		}
	}
	return maps.Keys(libs)
}
