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
	muslRegexp = regexp.MustCompile(`ld-musl[\.-]`)
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
		links []link.Link
		err   error
	)

	for _, libPath := range getPthreadLibs(pid) {
		if links, err = t.attachPythonUprobes(libPath, pid); err == nil {
			log(libPath, "python uprobes attached", nil)
			return links
		} else {
			log(libPath, "failed to attach python uprobes", err)
		}
	}
	if len(links) > 0 {

	}
	return links
}

func (t *Tracer) attachPythonUprobes(libPath string, pid uint32) ([]link.Link, error) {
	exe, err := link.OpenExecutable(libPath)
	if err != nil {
		return nil, err
	}
	ef, err := OpenELFFile(libPath)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

	s, err := ef.GetSymbol("pthread_cond_timedwait")
	if err != nil {
		return nil, err
	}
	l, err := s.AttachUprobe(exe, t.uprobes["pthread_cond_timedwait_enter"], pid)
	if err != nil {
		return nil, err
	}
	links := []link.Link{l}
	ls, err := s.AttachUretprobes(exe, t.uprobes["pthread_cond_timedwait_exit"], pid)
	links = append(links, ls...)
	if err != nil {
		for _, l := range links {
			_ = l.Close()
		}
		return nil, err
	}
	return links, nil
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
