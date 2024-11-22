package ebpftracer

import (
	"bufio"
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
	"k8s.io/klog/v2"
)

const (
	goTlsWriteSymbol = "crypto/tls.(*Conn).Write"
	goTlsReadSymbol  = "crypto/tls.(*Conn).Read"
)

var (
	opensslVersionRe = regexp.MustCompile(`OpenSSL\s(\d\.\d+\.\d+)`)
)

func (t *Tracer) AttachOpenSslUprobes(pid uint32) []link.Link {
	if t.disableL7Tracing {
		return nil
	}
	libPath, version := getSslLibPathAndVersion(pid)
	if libPath == "" || version == "" {
		return nil
	}

	log := func(msg string, err error) {
		if err != nil {
			for _, s := range []string{"no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					return
				}
			}
			klog.ErrorfDepth(1, "pid=%d libssl_version=%s: %s: %s", pid, version, msg, err)
			return
		}
		klog.InfofDepth(1, "pid=%d libssl_version=%s: %s", pid, version, msg)
	}

	exe, err := link.OpenExecutable(libPath)
	if err != nil {
		log("failed to open executable", err)
		return nil
	}
	var links []link.Link
	writeEnter := "openssl_SSL_write_enter"
	readEnter := "openssl_SSL_read_enter"
	readExEnter := "openssl_SSL_read_ex_enter"
	readExit := "openssl_SSL_read_exit"
	v, err := common.VersionFromString(version)
	if err != nil {
		log("failed to determine version", err)
		return nil
	}
	switch {
	case v.GreaterOrEqual(common.NewVersion(3, 0, 0)):
		writeEnter = "openssl_SSL_write_enter_v3_0"
		readEnter = "openssl_SSL_read_enter_v3_0"
		readExEnter = "openssl_SSL_read_ex_enter_v3_0"
	case v.GreaterOrEqual(common.NewVersion(1, 1, 1)):
		writeEnter = "openssl_SSL_write_enter_v1_1_1"
		readEnter = "openssl_SSL_read_enter_v1_1_1"
		readExEnter = "openssl_SSL_read_ex_enter_v1_1_1"
	}

	type prog struct {
		symbol    string
		uprobe    string
		uretprobe string
	}
	progs := []prog{
		{symbol: "SSL_write", uprobe: writeEnter},
		{symbol: "SSL_read", uprobe: readEnter},
		{symbol: "SSL_read", uretprobe: readExit},
	}
	if v.GreaterOrEqual(common.NewVersion(1, 1, 1)) {
		progs = append(progs, []prog{
			{symbol: "SSL_write_ex", uprobe: writeEnter},
			{symbol: "SSL_read_ex", uprobe: readExEnter},
			{symbol: "SSL_read_ex", uretprobe: readExit},
		}...)
	}
	for _, p := range progs {
		if p.uprobe != "" {
			l, err := exe.Uprobe(p.symbol, t.uprobes[p.uprobe], nil)
			if err != nil {
				log("failed to attach uprobe", err)
				return nil
			}
			links = append(links, l)
		}
		if p.uretprobe != "" {
			l, err := exe.Uretprobe(p.symbol, t.uprobes[p.uretprobe], nil)
			if err != nil {
				log("failed to attach uretprobe", err)
				return nil
			}
			links = append(links, l)
		}
	}

	log("libssl uprobes attached", nil)
	return links
}

func (t *Tracer) AttachGoTlsUprobes(pid uint32) ([]link.Link, bool) {
	isGolangApp := false
	if t.disableL7Tracing {
		return nil, isGolangApp
	}

	path := proc.Path(pid, "exe")

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

	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		log("failed to read build info", err)
		return nil, isGolangApp
	}
	isGolangApp = true

	name, err = os.Readlink(path)
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

	ef, err := elf.Open(path)
	if err != nil {
		log("failed to open as elf binary", err)
		return nil, isGolangApp
	}
	defer ef.Close()

	symbols, err := ef.Symbols()
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			log("no symbol section", nil)
			return nil, isGolangApp
		}
		log("failed to read symbols", err)
		return nil, isGolangApp
	}

	textSection := ef.Section(".text")
	if textSection == nil {
		log("no text section", nil)
		return nil, isGolangApp
	}
	textSectionData, err := textSection.Data()
	if err != nil {
		log("failed to read text section", err)
		return nil, isGolangApp
	}
	textSectionLen := uint64(len(textSectionData) - 1)

	exe, err := link.OpenExecutable(path)
	if err != nil {
		log("failed to open executable", err)
		return nil, isGolangApp
	}

	var links []link.Link
	for _, s := range symbols {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 {
			continue
		}
		switch s.Name {
		case goTlsWriteSymbol, goTlsReadSymbol:
		default:
			continue
		}
		address := s.Value
		for _, p := range ef.Progs {
			if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
				continue
			}

			if p.Vaddr <= s.Value && s.Value < (p.Vaddr+p.Memsz) {
				address = s.Value - p.Vaddr + p.Off
				break
			}
		}
		switch s.Name {
		case goTlsWriteSymbol:
			l, err := exe.Uprobe(s.Name, t.uprobes["go_crypto_tls_write_enter"], &link.UprobeOptions{Address: address})
			if err != nil {
				log("failed to attach write_enter uprobe", err)
				return nil, isGolangApp
			}
			links = append(links, l)
		case goTlsReadSymbol:
			l, err := exe.Uprobe(s.Name, t.uprobes["go_crypto_tls_read_enter"], &link.UprobeOptions{Address: address})
			if err != nil {
				log("failed to attach read_enter uprobe", err)
				return nil, isGolangApp
			}
			links = append(links, l)
			sStart := s.Value - textSection.Addr
			sEnd := sStart + s.Size
			if sEnd > textSectionLen {
				continue
			}
			sBytes := textSectionData[sStart:sEnd]
			returnOffsets := getReturnOffsets(ef.Machine, sBytes)
			if len(returnOffsets) == 0 {
				log("failed to attach read_exit uprobe", fmt.Errorf("no return offsets found"))
				return nil, isGolangApp
			}
			for _, offset := range returnOffsets {
				l, err := exe.Uprobe(s.Name, t.uprobes["go_crypto_tls_read_exit"], &link.UprobeOptions{Address: address, Offset: uint64(offset)})
				if err != nil {
					log("failed to attach read_exit uprobe", err)
					return nil, isGolangApp
				}
				links = append(links, l)
			}
		}
	}
	if len(links) == 0 {
		return nil, isGolangApp
	}
	log("crypto/tls uprobes attached", nil)
	return links, isGolangApp
}

func getSslLibPathAndVersion(pid uint32) (string, string) {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return "", ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	var libsslPath, libcryptoPath string
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) <= 5 {
			continue
		}
		libPath := parts[5]
		switch {
		case libsslPath == "" && strings.Contains(libPath, "libssl.so"):
			fullPath := proc.Path(pid, "root", libPath)
			if _, err = os.Stat(fullPath); err == nil {
				libsslPath = fullPath
			}
		case libcryptoPath == "" && strings.Contains(libPath, "libcrypto.so"):
			fullPath := proc.Path(pid, "root", libPath)
			if _, err = os.Stat(fullPath); err == nil {
				libcryptoPath = fullPath
			}
		default:
			continue
		}
		if libsslPath != "" && libcryptoPath != "" {
			break
		}
	}
	if libsslPath == "" || libcryptoPath == "" {
		return "", ""
	}

	ef, err := elf.Open(libcryptoPath)
	if err != nil {
		return "", ""
	}
	defer ef.Close()
	rodataSection := ef.Section(".rodata")
	if rodataSection == nil {
		return "", ""
	}
	rodataSectionData, err := rodataSection.Data()
	if err != nil {
		return "", ""
	}
	var version string
	for _, b := range bytes.Split(rodataSectionData, []byte("\x00")) {
		if len(b) == 0 {
			continue
		}
		s := string(b)
		if !strings.HasPrefix(s, "OpenSSL") {
			continue
		}
		if m := opensslVersionRe.FindStringSubmatch(s); len(m) > 1 {
			version = m[1]
		}
	}
	return libsslPath, "v" + version
}

func getReturnOffsets(machine elf.Machine, instructions []byte) []int {
	var res []int
	switch machine {
	case elf.EM_X86_64:
		for i := 0; i < len(instructions); {
			ins, err := x86asm.Decode(instructions[i:], 64)
			if err == nil && ins.Op == x86asm.RET {
				res = append(res, i)
			}
			i += ins.Len
		}
	case elf.EM_AARCH64:
		for i := 0; i < len(instructions); {
			ins, err := arm64asm.Decode(instructions[i:])
			if err == nil && ins.Op == arm64asm.RET {
				res = append(res, i)
			}
			i += 4
		}
	}
	return res
}
