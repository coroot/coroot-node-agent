package proc

import (
	"bufio"
	"os"
	"strings"
)

type Flags struct {
	EbpfProfilingDisabled bool
}

func GetFlags(pid uint32) (Flags, error) {
	flags := Flags{}
	f, err := os.Open(Path(pid, "environ"))
	if err != nil {
		return Flags{}, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString(0)
		if err != nil {
			break
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if !strings.HasPrefix(kv[0], "COROOT_") {
			continue
		}
		switch kv[0] {
		case "COROOT_EBPF_PROFILING":
			flags.EbpfProfilingDisabled = strings.Contains(kv[1], "disabled")
		}
	}
	return flags, nil
}
