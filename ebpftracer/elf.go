package ebpftracer

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

type Symbol struct {
	s       *elf.Symbol
	f       *ELFFile
	address uint64
}

func (s *Symbol) Name() string {
	return s.s.Name
}

func (s *Symbol) Address() uint64 {
	if s.address == 0 {
		s.address = s.s.Value
		for _, p := range s.f.elf.Progs {
			if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
				continue
			}
			if p.Vaddr <= s.s.Value && s.s.Value < (p.Vaddr+p.Memsz) {
				s.address = s.s.Value - p.Vaddr + p.Off
				break
			}
		}
	}
	return s.address
}

func (s *Symbol) ReturnOffsets() ([]int, error) {
	text, reader, err := s.f.getTextSectionAndReader()
	if err != nil {
		return nil, err
	}

	sStart := s.s.Value - text.Addr
	_, err = reader.Seek(int64(sStart), io.SeekStart)
	if err != nil {
		return nil, err
	}
	sBytes := make([]byte, s.s.Size)
	_, err = reader.Read(sBytes)
	if err != nil {
		return nil, err
	}

	offsets := getReturnOffsets(s.f.elf.Machine, sBytes)
	if len(offsets) == 0 {
		return nil, fmt.Errorf("no offsets found")
	}
	return offsets, nil
}

func (s *Symbol) AttachUprobe(exe *link.Executable, prog *ebpf.Program, pid uint32) (link.Link, error) {
	return exe.Uprobe(s.Name(), prog, &link.UprobeOptions{Address: s.Address(), PID: int(pid)})
}

func (s *Symbol) AttachUretprobes(exe *link.Executable, prog *ebpf.Program, pid uint32) ([]link.Link, error) {
	returnOffsets, err := s.ReturnOffsets()
	if err != nil {
		return nil, err
	}
	var links []link.Link
	for _, offset := range returnOffsets {
		l, err := exe.Uprobe(s.Name(), prog, &link.UprobeOptions{Address: s.Address(), Offset: uint64(offset), PID: int(pid)})
		if err != nil {
			return links, err
		}
		links = append(links, l)
	}

	return links, nil
}

type ELFFile struct {
	elf               *elf.File
	symbols           []elf.Symbol
	textSection       *elf.Section
	textSectionReader io.ReadSeeker
}

func OpenELFFile(path string) (*ELFFile, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	return &ELFFile{elf: file}, nil
}

func (f *ELFFile) readSymbols() error {
	symbols, _ := f.elf.Symbols()
	dyn, _ := f.elf.DynamicSymbols()

	if len(symbols) == 0 && len(dyn) == 0 {
		return fmt.Errorf("no symbols found")
	}
	f.symbols = append(symbols, dyn...)
	return nil
}

func (f *ELFFile) GetSymbol(name string) (*Symbol, error) {
	if f.symbols == nil {
		if err := f.readSymbols(); err != nil {
			return nil, err
		}
	}
	var es *elf.Symbol
	for _, s := range f.symbols {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 || s.Value == 0 {
			continue
		}
		if s.Name == name && s.VersionIndex&0x8000 == 0 {
			es = &s
			break
		}
	}
	if es == nil {
		return nil, fmt.Errorf("symbol %s not found", name)
	}
	return &Symbol{s: es, f: f}, nil
}

func (f *ELFFile) FindSymbolValue(name string) (uint64, error) {
	return findSymbolValue(f.elf, ".symtab", name)
}

func findSymbolValue(ef *elf.File, sectionName, symName string) (uint64, error) {
	section := ef.Section(sectionName)
	if section == nil {
		return 0, fmt.Errorf("no %s section", sectionName)
	}
	strtab := ef.Sections[section.Link]
	if strtab == nil {
		return 0, fmt.Errorf("no string table for %s", sectionName)
	}

	entrySize := int64(24) // Elf64_Sym
	if ef.Class == elf.ELFCLASS32 {
		entrySize = 16 // Elf32_Sym
	}

	symReader := section.Open()
	entry := make([]byte, entrySize)
	target := []byte(symName)
	nameBuf := make([]byte, len(target)+1)

	// skip entry 0 (undefined symbol)
	if _, err := symReader.Read(entry); err != nil {
		return 0, fmt.Errorf("read %s: %w", sectionName, err)
	}

	for {
		if _, err := symReader.Read(entry); err != nil {
			break
		}
		nameIdx := ef.ByteOrder.Uint32(entry[0:4])
		var value uint64
		if ef.Class == elf.ELFCLASS64 {
			value = ef.ByteOrder.Uint64(entry[8:16])
		} else {
			value = uint64(ef.ByteOrder.Uint32(entry[4:8]))
		}
		if nameIdx == 0 {
			continue
		}
		n, _ := strtab.ReadAt(nameBuf, int64(nameIdx))
		if n < len(target) {
			continue
		}
		if n > len(target) && nameBuf[len(target)] != 0 {
			continue
		}
		if string(nameBuf[:len(target)]) == symName {
			return value, nil
		}
	}
	return 0, fmt.Errorf("%s not found", symName)
}

func (f *ELFFile) FindSymbolBySubstrings(substrs ...string) *Symbol {
	if f.symbols == nil {
		if err := f.readSymbols(); err != nil {
			return nil
		}
	}
	for _, s := range f.symbols {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 || s.Value == 0 {
			continue
		}
		name := []byte(s.Name)
		match := true
		for _, sub := range substrs {
			if !bytes.Contains(name, []byte(sub)) {
				match = false
				break
			}
		}
		if match {
			es := s
			return &Symbol{s: &es, f: f}
		}
	}
	return nil
}

func (f *ELFFile) getTextSectionAndReader() (*elf.Section, io.ReadSeeker, error) {
	if f.textSection == nil {
		f.textSection = f.elf.Section(".text")
		if f.textSection == nil {
			return nil, nil, fmt.Errorf("no .text")
		}
		f.textSectionReader = f.textSection.Open()
	}
	return f.textSection, f.textSectionReader, nil
}

func (f *ELFFile) IsGoBinary() bool {
	return f.elf.Section(".go.buildinfo") != nil
}

func (f *ELFFile) IsRustBinary() bool {
	section := f.elf.Section(".comment")
	if section == nil {
		return false
	}
	data, err := section.Data()
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte("rustc version"))
}

func (f *ELFFile) Close() error {
	return f.elf.Close()
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
