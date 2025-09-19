package ebpftracer

import (
	"bufio"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/proc"
	"golang.org/x/exp/maps"
	"k8s.io/klog/v2"
)

func (t *Tracer) AttachNodejsProbes(pid uint32, exe string) []link.Link {
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
	for _, libPath = range append(getLibuv(pid), proc.Path(pid, "root", exe)) {
		exe, err := link.OpenExecutable(libPath)
		if err != nil {
			log(libPath, "failed to open executable", err)
			return nil
		}
		options := &link.UprobeOptions{PID: int(pid)}
		var uprobe, uretprobe link.Link
		uprobe, lastErr = exe.Uprobe("uv__io_poll", t.uprobes["uv_io_poll_enter"], options)
		if lastErr != nil {
			continue
		}

		links = append(links, uprobe)
		uretprobe, lastErr = exe.Uretprobe("uv__io_poll", t.uprobes["uv_io_poll_exit"], options)
		if lastErr != nil {
			continue
		}

		links = append(links, uretprobe)

		for _, cb := range []string{"uv__stream_io", "uv__async_io", "uv__poll_io", "uv__server_io", "uv__udp_io"} {
			uprobe, lastErr = exe.Uprobe(cb, t.uprobes["uv_io_cb_enter"], options)
			if lastErr != nil {
				break
			}
			links = append(links, uprobe)
			uretprobe, lastErr = exe.Uretprobe(cb, t.uprobes["uv_io_cb_exit"], options)
			if lastErr != nil {
				break
			}
			links = append(links, uretprobe)
		}
		if lastErr != nil {
			continue
		}

		log(libPath, "nodejs uprobes attached", nil)
		break
	}
	if lastErr != nil {
		log(libPath, "failed to attach uprobe", lastErr)
	}
	return links
}

func getLibuv(pid uint32) []string {
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
		if strings.Contains(libPath, "libuv") {
			libs[proc.Path(pid, "root", libPath)] = true
		}
	}
	return maps.Keys(libs)
}
