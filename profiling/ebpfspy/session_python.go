//go:build linux

package ebpfspy

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/coroot/coroot-node-agent/profiling/pyrobpf"
	"github.com/coroot/coroot-node-agent/profiling/python"
	"github.com/samber/lo"
	"k8s.io/klog/v2"
)

func (s *session) tryStartPythonProfiling(pid uint32, target *Target, pi procInfoLite) {
	const nTries = 4
	for i := 0; i < nTries; i++ {
		shouldRetry := s.startPythonProfiling(pid, target, pi, i == nTries-1)
		if !shouldRetry {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *session) startPythonProfiling(pid uint32, target *Target, pi procInfoLite, lastAttempt bool) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if !s.started {
		return false
	}
	_, dead := s.pids.dead[pid]
	if dead {
		return false
	}
	pyPerf := s.getPyPerfLocked()
	if pyPerf == nil {
		klog.Errorf("pid=%d: pyperf is not loaded", pid)
		pi.typ = pyrobpf.ProfilingTypeError
		s.setPidConfig(pid, pi)
		return false
	}

	pyData, err := python.GetPyPerfPidData(pid)
	svc := target.ServiceName
	if err != nil {
		alive := processAlive(pid)
		if alive && lastAttempt {
			klog.Warningf("pid=%d (%s): failed to get python process data: %v", pid, svc, err)
		}
		pi.typ = pyrobpf.ProfilingTypeError
		s.setPidConfig(pid, pi)
		return alive
	}
	err = nil
	proc := pyPerf.FindProc(pid)
	if proc == nil {
		proc, err = pyPerf.NewProc(pid, pyData, &s.options.SymbolOptions)
		if err != nil {
			klog.Errorf("pid=%d: pyperf process init failed: %v", pid, err)
			pi.typ = pyrobpf.ProfilingTypeError
			s.setPidConfig(pid, pi)
			return false
		}
	}
	klog.Infof("pid=%d (%s): python profiling enabled: python %d.%d.%d, musl=%t", pid, svc, pyData.Version.Major, pyData.Version.Minor, pyData.Version.Patch, pyData.Libc.Musl)
	s.setPidConfig(pid, pi)
	return false
}

// may return nil if loadPyPerf returns error
func (s *session) getPyPerfLocked() *python.Perf {
	if s.pyperf != nil {
		return s.pyperf
	}
	if s.pyperfError != nil {
		return nil
	}
	pyperf, err := s.loadPyPerf()
	if err != nil {
		s.pyperfError = err
		klog.Errorln("failed to load pyperf:", err)
		return nil
	}
	s.pyperf = pyperf
	return s.pyperf
}

// getPyPerf is used for testing to wait for pyperf to load
// it may take long time to load and verify, especially running in qemu with no kvm
func (s *session) getPyPerf() *python.Perf {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.getPyPerfLocked()
}

func (s *session) loadPyPerf() (*python.Perf, error) {
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"stacks": s.bpf.Stacks,
			"counts": s.bpf.ProfileMaps.Counts,
		},
	}
	spec, err := python.LoadPerf()
	if err != nil {
		return nil, fmt.Errorf("pyperf load %w", err)
	}
	_, nsIno, err := getPIDNamespace()
	if err != nil {
		return nil, fmt.Errorf("unable to get pid namespace %w", err)
	}
	v, ok := spec.Variables["global_config"]
	if !ok {
		return nil, fmt.Errorf("pyperf: variable global_config not found")
	}
	if err = v.Set(python.PerfGlobalConfigT{NsPidIno: nsIno}); err != nil {
		return nil, fmt.Errorf("pyperf set global_config: %w", err)
	}

	err = spec.LoadAndAssign(&s.pyperfBpf, opts)
	if err != nil {
		return nil, fmt.Errorf("pyperf load %w", err)
	}
	pyperf, err := python.NewPerf(s.pyperfBpf.PerfMaps.PyPidConfig, s.pyperfBpf.PerfMaps.PySymbols)
	if err != nil {
		return nil, fmt.Errorf("pyperf create %w", err)
	}
	err = s.bpf.ProfileMaps.Progs.Update(uint32(0), s.pyperfBpf.PerfPrograms.PyperfCollect, ebpf.UpdateAny)
	if err != nil {
		return nil, fmt.Errorf("pyperf link %w", err)
	}
	klog.Infoln("pyperf loaded")
	return pyperf, nil
}

func (s *session) GetPythonStack(stackId int64) []byte {
	if s.pyperfBpf.PythonStacks == nil {
		return nil
	}
	stackIdU32 := uint32(stackId)
	res, err := s.pyperfBpf.PythonStacks.LookupBytes(stackIdU32)
	if err != nil {
		return nil
	}
	return res
}

func (s *session) WalkPythonStack(sb *stackBuilder, stack []byte, proc *python.Proc, pySymbols *python.LazySymbols, stats *StackResolveStats) {
	if len(stack) == 0 {
		return
	}

	begin := len(sb.stack)
	for len(stack) > 0 {
		symbolIDBytes := stack[:4]
		stack = stack[4:]
		symbolID := binary.LittleEndian.Uint32(symbolIDBytes)
		if symbolID == 0 {
			break
		}
		sym, err := pySymbols.GetSymbol(symbolID)
		if err == nil {
			filename := python.PythonString(sym.File[:], &sym.FileType)
			if !proc.SymbolOptions.PythonFullFilePath {
				iSep := strings.LastIndexByte(filename, '/')
				if iSep != 1 {
					filename = filename[iSep+1:]
				}
			}
			classname := python.PythonString(sym.Classname[:], &sym.ClassnameType)
			name := python.PythonString(sym.Name[:], &sym.NameType)
			if skipPythonFrame(classname, filename, name) {
				continue
			}
			var frame string
			if classname == "" {
				frame = filename + " " + name
			} else {
				frame = filename + " " + classname + "." + name
			}
			sb.append(frame)
			stats.known += 1
		} else {
			sb.append("pyperf_unknown")
			stats.unknownSymbols += 1
		}
	}
	end := len(sb.stack)
	lo.Reverse(sb.stack[begin:end])
}

func skipPythonFrame(classname string, filename string, name string) bool {
	// for now only skip _Py_InitCleanup frames in userspace
	// https://github.com/python/cpython/blob/9eb2489266c4c1f115b8f72c0728db737cc8a815/Python/specialize.c#L2534
	return classname == "" && filename == "__init__" && name == "__init__"
}

func processAlive(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}
