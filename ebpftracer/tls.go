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

var silentErrors = []string{
	"not a Go executable",
	"not found",
	"no such file or directory",
	"no such process",
	"permission denied",
}

func uprobeLog(pid uint32, prefix string) func(string, error) {
	return func(msg string, err error) {
		if err != nil {
			for _, s := range silentErrors {
				if strings.HasSuffix(err.Error(), s) {
					return
				}
			}
			klog.ErrorfDepth(2, "pid=%d%s: %s: %s", pid, prefix, msg, err)
			return
		}
		klog.InfofDepth(2, "pid=%d%s: %s", pid, prefix, msg)
	}
}

type uprobeSpec struct {
	symbol    string
	uprobe    string
	uretprobe string
	optional  bool
}

func (t *Tracer) attachUprobes(exePath string, ef *ELFFile, specs []uprobeSpec, log func(string, error)) []link.Link {
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
	for _, s := range specs {
		sym, err := ef.GetSymbol(s.symbol)
		if err != nil {
			if s.optional {
				continue
			}
			log("failed to get symbol "+s.symbol, err)
			closeLinks()
			return nil
		}
		if s.uprobe != "" {
			l, err := sym.AttachUprobe(exe, t.uprobes[s.uprobe], 0)
			if err != nil {
				log("failed to attach uprobe "+s.uprobe, err)
				closeLinks()
				return nil
			}
			links = append(links, l)
		}
		if s.uretprobe != "" {
			ls, err := sym.AttachUretprobes(exe, t.uprobes[s.uretprobe], 0)
			links = append(links, ls...)
			if err != nil {
				log("failed to attach uretprobe "+s.uretprobe, err)
				closeLinks()
				return nil
			}
		}
	}
	return links
}

func (t *Tracer) AttachOpenSslUprobes(pid uint32) *UprobeKey {
	if t.disableL7Tracing {
		return nil
	}
	libPath := getSslLibPath(pid)
	if libPath == "" {
		return nil
	}
	log := uprobeLog(pid, "")
	key, ok := t.AcquireGlobalUprobe(libPath, func() []link.Link {
		ef, err := OpenELFFile(libPath)
		if err != nil {
			log("open elf", err)
			return nil
		}
		defer ef.Close()

		links := t.attachUprobes(libPath, ef, []uprobeSpec{
			{symbol: "SSL_write", uprobe: "openssl_SSL_write_enter"},
			{symbol: "SSL_read", uprobe: "openssl_SSL_read_enter"},
			{symbol: "SSL_read", uretprobe: "openssl_SSL_read_exit"},
			{symbol: "SSL_write_ex", uprobe: "openssl_SSL_write_enter", optional: true},
			{symbol: "SSL_read_ex", uprobe: "openssl_SSL_read_ex_enter", optional: true},
			{symbol: "SSL_read_ex", uretprobe: "openssl_SSL_read_exit", optional: true},
		}, log)
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

	var name, version string
	log := func(msg string, err error) {
		prefix := " golang_app=" + name + " golang_version=" + version
		uprobeLog(pid, prefix)(msg, err)
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

		links := t.attachUprobes(exePath, ef, []uprobeSpec{
			{symbol: goTlsWriteSymbol, uprobe: "go_crypto_tls_write_enter"},
			{symbol: goTlsReadSymbol, uprobe: "go_crypto_tls_read_enter"},
			{symbol: goTlsReadSymbol, uretprobe: "go_crypto_tls_read_exit"},
		}, log)
		if len(links) > 0 {
			log("crypto/tls uprobes attached", nil)
		}
		return links
	})
	if ok {
		return &key, isGolangApp
	}
	return nil, isGolangApp
}

func (t *Tracer) AttachRustlsUprobes(pid uint32) (*UprobeKey, bool) {
	isRustApp := false
	if t.disableL7Tracing {
		return nil, isRustApp
	}

	exePath := proc.Path(pid, "exe")
	log := uprobeLog(pid, "")

	ef, err := OpenELFFile(exePath)
	if err != nil {
		return nil, isRustApp
	}
	defer ef.Close()

	if !ef.IsRustBinary() {
		return nil, isRustApp
	}
	isRustApp = true

	name, err := os.Readlink(exePath)
	if err != nil {
		log("failed to read name", err)
		return nil, isRustApp
	}

	writerWrite := ef.FindSymbolBySubstrings("rustls", "Writer", "write")
	if writerWrite == nil {
		return nil, isRustApp
	}

	readerRead := ef.FindSymbolBySubstrings("rustls", "Reader", "read")
	if readerRead == nil {
		return nil, isRustApp
	}

	key, ok := t.AcquireGlobalUprobe(proc.Path(pid, "root", name), func() []link.Link {
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
		l, err := writerWrite.AttachUprobe(exe, t.uprobes["rustls_write_enter"], 0)
		if err != nil {
			log("failed to attach rustls write_enter uprobe", err)
			return nil
		}
		links = append(links, l)

		l, err = readerRead.AttachUprobe(exe, t.uprobes["rustls_read_enter"], 0)
		if err != nil {
			log("failed to attach rustls read_enter uprobe", err)
			closeLinks()
			return nil
		}
		links = append(links, l)

		ls, err := readerRead.AttachUretprobes(exe, t.uprobes["rustls_read_exit"], 0)
		links = append(links, ls...)
		if err != nil {
			log("failed to attach rustls read_exit uprobe", err)
			closeLinks()
			return nil
		}

		if len(links) > 0 {
			log("rustls uprobes attached", nil)
		}
		return links
	})
	if ok {
		return &key, isRustApp
	}
	return nil, isRustApp
}

func (t *Tracer) AttachJavaTlsUprobes(pid uint32, nativeLibPath string) *UprobeKey {
	if t.disableL7Tracing {
		return nil
	}
	log := uprobeLog(pid, "")
	key, ok := t.AcquireGlobalUprobe(nativeLibPath, func() []link.Link {
		ef, err := OpenELFFile(nativeLibPath)
		if err != nil {
			log("open elf", err)
			return nil
		}
		defer ef.Close()

		links := t.attachUprobes(nativeLibPath, ef, []uprobeSpec{
			{symbol: "coroot_java_tls_write_enter", uprobe: "java_tls_write_enter"},
			{symbol: "coroot_java_tls_read_exit", uprobe: "java_tls_read_exit"},
		}, log)
		if len(links) > 0 {
			log("java TLS uprobes attached (global)", nil)
		}
		return links
	})
	if ok {
		return &key
	}
	return nil
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
