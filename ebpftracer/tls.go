package ebpftracer

import (
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/proc"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/mod/semver"
	"k8s.io/klog/v2"
	"os"
	"strings"
)

const (
	minSupportedGoVersion = "v1.17.0"
	writeSymbol           = "crypto/tls.(*Conn).Write"
	readSymbol            = "crypto/tls.(*Conn).Read"
)

func (t *Tracer) AttachGoTlsUprobes(pid uint32) []link.Link {
	if t.disableL7Tracing {
		return nil
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
		return nil
	}

	name, err = os.Readlink(path)
	if err != nil {
		log("failed to read name", err)
		return nil
	}
	version = strings.Replace(bi.GoVersion, "go", "v", 1)
	if semver.Compare(version, minSupportedGoVersion) < 0 {
		log(fmt.Sprintf("go_versions below %s are not supported", minSupportedGoVersion), nil)
		return nil
	}

	ef, err := elf.Open(path)
	if err != nil {
		log("failed to open as elf binary", err)
		return nil
	}
	defer ef.Close()

	symbols, err := ef.Symbols()
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			log("no symbol section", nil)
			return nil
		}
		log("failed to read symbols", err)
		return nil
	}

	textSection := ef.Section(".text")
	if textSection == nil {
		log("no text section", nil)
		return nil
	}
	textSectionData, err := textSection.Data()
	if err != nil {
		log("failed to read text section", err)
		return nil
	}
	textSectionLen := uint64(len(textSectionData) - 1)

	exe, err := link.OpenExecutable(path)
	if err != nil {
		log("failed to open executable", err)
		return nil
	}

	var links []link.Link
	for _, s := range symbols {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 {
			continue
		}
		switch s.Name {
		case writeSymbol, readSymbol:
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
		case writeSymbol:
			l, err := exe.Uprobe(s.Name, t.uprobes["go_crypto_tls_write_enter"], &link.UprobeOptions{Address: address})
			if err != nil {
				log("failed to attach write_enter uprobe", err)
				return nil
			}
			links = append(links, l)
		case readSymbol:
			l, err := exe.Uprobe(s.Name, t.uprobes["go_crypto_tls_read_enter"], &link.UprobeOptions{Address: address})
			if err != nil {
				log("failed to attach read_enter uprobe", err)
				return nil
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
				return nil
			}
			for _, offset := range returnOffsets {
				l, err := exe.Uprobe(s.Name, t.uprobes["go_crypto_tls_read_exit"], &link.UprobeOptions{Address: address, Offset: uint64(offset)})
				if err != nil {
					log("failed to attach read_exit uprobe", err)
					return nil
				}
				links = append(links, l)
			}
		}
	}
	if len(links) == 0 {
		return nil
	}
	log("crypto/tls uprobes attached", nil)
	return links
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
