package ebpftracer

import (
	"bufio"
	"debug/buildinfo"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

const (
	goTlsWriteSymbol = "crypto/tls.(*Conn).Write"
	goTlsReadSymbol  = "crypto/tls.(*Conn).Read"
)

func (t *Tracer) AttachOpenSslUprobes(pid uint32) *UprobeKey {
	if t.disableL7Tracing {
		return nil
	}
	libPath := getSslLibPath(pid)
	if libPath == "" {
		return nil
	}

	log := func(msg string, err error) {
		if err != nil {
			for _, s := range []string{"no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					return
				}
			}
			klog.ErrorfDepth(1, "pid=%d: %s: %s", pid, msg, err)
			return
		}
		klog.InfofDepth(1, "pid=%d: %s", pid, msg)
	}

	key, ok := t.AcquireGlobalUprobe(libPath, func() []link.Link {
		exe, err := link.OpenExecutable(libPath)
		if err != nil {
			log("failed to open executable", err)
			return nil
		}
		var links []link.Link
		closeLinks := func() {
			for _, l := range links {
				l.Close()
			}
		}

		ef, err := OpenELFFile(libPath)
		if err != nil {
			log("open elf", err)
			return nil
		}
		defer ef.Close()

		type prog struct {
			symbol    string
			uprobe    string
			uretprobe string
			optional  bool
		}
		progs := []prog{
			{symbol: "SSL_write", uprobe: "openssl_SSL_write_enter"},
			{symbol: "SSL_read", uprobe: "openssl_SSL_read_enter"},
			{symbol: "SSL_read", uretprobe: "openssl_SSL_read_exit"},
			{symbol: "SSL_write_ex", uprobe: "openssl_SSL_write_enter", optional: true},
			{symbol: "SSL_read_ex", uprobe: "openssl_SSL_read_ex_enter", optional: true},
			{symbol: "SSL_read_ex", uretprobe: "openssl_SSL_read_exit", optional: true},
		}

		for _, p := range progs {
			s, err := ef.GetSymbol(p.symbol)
			if err != nil {
				if p.optional {
					continue
				}
				log("failed to get symbol", err)
				closeLinks()
				return nil
			}
			if p.uprobe != "" {
				l, err := s.AttachUprobe(exe, t.uprobes[p.uprobe], 0)
				if err != nil {
					log("failed to attach uprobe", err)
					closeLinks()
					return nil
				}
				links = append(links, l)
			}
			if p.uretprobe != "" {
				ls, err := s.AttachUretprobes(exe, t.uprobes[p.uretprobe], 0)
				links = append(links, ls...)
				if err != nil {
					log("failed to attach exit uprobe", err)
					closeLinks()
					return nil
				}
			}
		}
		if len(links) > 0 {
			log("libssl uprobes attached (global)", nil)
		}
		return links
	})
	if ok {
		return &key
	}
	return nil
}

func (t *Tracer) AttachGoTlsUprobes(pid uint32) (*UprobeKey, bool) {
	isGolangApp := false
	if t.disableL7Tracing {
		return nil, isGolangApp
	}

	exePath := proc.Path(pid, "exe")

	var err error
	var name, version string
	log := func(msg string, err error) {
		if err != nil {
			for _, s := range []string{"not a Go executable", "no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					return
				}
			}
			klog.ErrorfDepth(1, "pid=%d golang_app=%s golang_version=%s: %s: %s", pid, name, version, msg, err)
			return
		}
		klog.InfofDepth(1, "pid=%d golang_app=%s golang_version=%s: %s", pid, name, version, msg)
	}

	bi, err := buildinfo.ReadFile(exePath)
	if err != nil {
		log("failed to read build info", err)
		return nil, isGolangApp
	}
	isGolangApp = true

	name, err = os.Readlink(exePath)
	if err != nil {
		log("failed to read name", err)
		return nil, isGolangApp
	}
	version = bi.GoVersion
	v, err := common.VersionFromString(strings.Replace(bi.GoVersion, "go", "", 1))
	if err != nil {
		log("failed to determine version", err)
	}
	if !v.GreaterOrEqual(common.NewVersion(1, 17, 0)) {
		log("versions below 1.17 are not supported", nil)
		return nil, isGolangApp
	}

	key, ok := t.AcquireGlobalUprobe(proc.Path(pid, "root", name), func() []link.Link {
		ef, err := OpenELFFile(exePath)
		if err != nil {
			log("failed to open as elf binary", err)
			return nil
		}
		defer ef.Close()

		exe, err := link.OpenExecutable(exePath)
		if err != nil {
			log("failed to open executable", err)
			return nil
		}

		var links []link.Link
		closeLinks := func() {
			for _, l := range links {
				l.Close()
			}
		}

		ws, err := ef.GetSymbol(goTlsWriteSymbol)
		if err != nil {
			log("failed to get symbol", err)
			return nil
		}
		l, err := ws.AttachUprobe(exe, t.uprobes["go_crypto_tls_write_enter"], 0)
		if err != nil {
			log("failed to attach write_enter uprobe", err)
			return nil
		}
		links = append(links, l)

		rs, err := ef.GetSymbol(goTlsReadSymbol)
		if err != nil {
			log("failed to get symbol", err)
			return nil
		}
		l, err = rs.AttachUprobe(exe, t.uprobes["go_crypto_tls_read_enter"], 0)
		if err != nil {
			log("failed to attach read_enter uprobe", err)
			closeLinks()
			return nil
		}
		links = append(links, l)

		ls, err := rs.AttachUretprobes(exe, t.uprobes["go_crypto_tls_read_exit"], 0)
		links = append(links, ls...)
		if err != nil {
			log("failed to attach read_exit uprobe", err)
			closeLinks()
			return nil
		}
		if len(links) == 0 {
			return nil
		}
		log("crypto/tls uprobes attached", nil)
		return links
	})
	if ok {
		return &key, isGolangApp
	}
	return nil, isGolangApp
}

func getSslLibPath(pid uint32) string {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) <= 5 {
			continue
		}
		libPath := parts[5]
		if strings.Contains(libPath, "libssl.so") {
			fullPath := proc.Path(pid, "root", libPath)
			if _, err = os.Stat(fullPath); err == nil {
				return fullPath
			}
		}
	}
	return ""
}
