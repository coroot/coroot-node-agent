package profiling

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/google/pprof/profile"
	"github.com/grafana/pyroscope/ebpf/symtab"
	"k8s.io/klog/v2"
)

const (
	profileTypeAllocObjects = "go_runtime:heap_alloc_objects:count"
	profileTypeAllocSpace   = "go_runtime:heap_alloc_space:bytes"
	profileTypeInuseObjects = "go_runtime:heap_inuse_objects:count"
	profileTypeInuseSpace   = "go_runtime:heap_inuse_space:bytes"

	bucketHeaderSize   = 48 // 6 * 8 bytes (sys.NotInHeap is zero-sized)
	memRecordCycleSize = 32 // 4 * 8 bytes
	memProfileType     = 1
	maxBuckets         = 100000
	maxStackDepth      = 1024 // matches runtime.maxProfStackDepth; actual depth controlled by debug.profstackdepth (default 128)
)

type goHeapProfile struct {
	Type string
	Prof *profile.Profile
}

type goHeapPrevState map[uint64]prevValues

type prevValues struct {
	allocObjects int64
	allocBytes   int64
}

type sampleAcc struct {
	locs         []*profile.Location
	allocObjects int64
	allocBytes   int64
	inuseObjects int64
	inuseBytes   int64
}

const defaultMemProfileRate = 512 * 1024

func findMbucketsAddr(pid uint32, mode string) (uint64, error) {
	exePath := proc.Path(pid, "exe")
	f, err := ebpftracer.OpenELFFile(exePath)
	if err != nil {
		return 0, fmt.Errorf("open ELF: %w", err)
	}
	defer f.Close()

	if !f.IsGoBinary() {
		return 0, fmt.Errorf("not a Go binary")
	}

	mbucketsAddr, err := f.FindSymbolValue("runtime.mbuckets")
	if err != nil {
		return 0, err
	}
	if mbucketsAddr == 0 {
		return 0, fmt.Errorf("runtime.mbuckets has zero address")
	}

	rateAddr, err := f.FindSymbolValue("runtime.MemProfileRate")
	if err != nil {
		return mbucketsAddr, nil
	}

	openFlags := os.O_RDONLY
	if mode == "force" {
		openFlags = os.O_RDWR
	}
	memPath := proc.Path(pid, "mem")
	mem, err := os.OpenFile(memPath, openFlags, 0)
	if err != nil {
		return mbucketsAddr, nil
	}
	defer mem.Close()

	rate, err := readUint64(mem, rateAddr)
	if err != nil {
		return mbucketsAddr, nil
	}
	if rate != 0 {
		klog.Infof("pid=%d: memory profiling already enabled (MemProfileRate=%d)", pid, rate)
		return mbucketsAddr, nil
	}

	if mode != "force" {
		klog.Infof("pid=%d: memory profiling is disabled, skipping (use --go-heap-profiler=force to enable)", pid)
		return 0, fmt.Errorf("memory profiling disabled")
	}

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, defaultMemProfileRate)
	if _, err := mem.WriteAt(buf, int64(rateAddr)); err != nil {
		klog.Warningf("pid=%d: failed to enable memory profiling: %v", pid, err)
		return mbucketsAddr, nil
	}
	klog.Infof("pid=%d: memory profiling was disabled, enabled by agent (MemProfileRate=%d)", pid, defaultMemProfileRate)
	return mbucketsAddr, nil
}

type memRecordCycle struct {
	Allocs     uint64
	Frees      uint64
	AllocBytes uint64
	FreeBytes  uint64
}

type bucketData struct {
	addr   uint64
	size   uint64
	stk    []uint64
	active memRecordCycle
}

func collectHeapProfile(pid uint32, mbucketsAddr uint64, duration time.Duration, symCache *symtab.SymbolCache, prev goHeapPrevState, r *memReader) ([]goHeapProfile, goHeapPrevState, error) {
	memPath := proc.Path(pid, "mem")
	mem, err := os.Open(memPath)
	if err != nil {
		return nil, prev, fmt.Errorf("open %s: %w", memPath, err)
	}
	defer mem.Close()
	r.reset(mem)

	head, err := readUint64(mem, mbucketsAddr)
	if err != nil {
		return nil, prev, fmt.Errorf("read mbuckets pointer: %w", err)
	}
	if head == 0 {
		return nil, prev, nil
	}

	buckets, err := readBuckets(r, head)
	if err != nil {
		return nil, prev, fmt.Errorf("read buckets: %w", err)
	}
	if len(buckets) == 0 {
		return nil, prev, nil
	}

	var resolver func(uint64) string
	if symCache != nil {
		if pt := symCache.GetProcTableCached(symtab.PidKey(pid)); pt != nil {
			resolver = func(pc uint64) string {
				return pt.Resolve(pc).Name
			}
		}
	}

	profiles, newPrev := buildProfiles(buckets, resolver, duration, prev)
	return profiles, newPrev, nil
}

type memReader struct {
	f         *os.File
	buf       []byte
	base      uint64
	validSize int
}

const memReaderChunkSize = 256 * 1024

func newMemReader() *memReader {
	return &memReader{buf: make([]byte, memReaderChunkSize)}
}

func (r *memReader) reset(f *os.File) {
	r.f = f
	r.base = 0
	r.validSize = 0
}

func (r *memReader) readAt(p []byte, addr uint64) error {
	end := addr + uint64(len(p))
	if addr >= r.base && end <= r.base+uint64(r.validSize) {
		copy(p, r.buf[addr-r.base:end-r.base])
		return nil
	}
	readAddr := addr
	if addr > memReaderChunkSize/2 {
		readAddr = addr - memReaderChunkSize/2
	} else {
		readAddr = 0
	}
	n, err := r.f.ReadAt(r.buf, int64(readAddr))
	r.base = readAddr
	r.validSize = n
	if addr+uint64(len(p)) > readAddr+uint64(n) {
		if err != nil {
			return err
		}
		return fmt.Errorf("short read")
	}
	copy(p, r.buf[addr-readAddr:addr-readAddr+uint64(len(p))])
	return nil
}

func readBuckets(r *memReader, head uint64) ([]bucketData, error) {
	var buckets []bucketData
	addr := head
	seen := make(map[uint64]bool)
	hdrBuf := make([]byte, bucketHeaderSize)
	dataBuf := make([]byte, maxStackDepth*8+memRecordCycleSize)

	for addr != 0 && len(buckets) < maxBuckets {
		if seen[addr] {
			break
		}
		seen[addr] = true

		if err := r.readAt(hdrBuf, addr); err != nil {
			return buckets, nil
		}
		allnext := binary.LittleEndian.Uint64(hdrBuf[8:16])
		typ := binary.LittleEndian.Uint64(hdrBuf[16:24])
		size := binary.LittleEndian.Uint64(hdrBuf[32:40])
		nstk := binary.LittleEndian.Uint64(hdrBuf[40:48])

		if typ != memProfileType || nstk > maxStackDepth {
			addr = allnext
			continue
		}

		dataSize := nstk*8 + memRecordCycleSize
		if err := r.readAt(dataBuf[:dataSize], addr+bucketHeaderSize); err != nil {
			return buckets, nil
		}

		rec := dataBuf[nstk*8:]
		active := memRecordCycle{
			Allocs:     binary.LittleEndian.Uint64(rec[0:8]),
			Frees:      binary.LittleEndian.Uint64(rec[8:16]),
			AllocBytes: binary.LittleEndian.Uint64(rec[16:24]),
			FreeBytes:  binary.LittleEndian.Uint64(rec[24:32]),
		}

		if active.Allocs > 0 || active.AllocBytes > 0 {
			stk := make([]uint64, nstk)
			for i := uint64(0); i < nstk; i++ {
				stk[i] = binary.LittleEndian.Uint64(dataBuf[i*8 : (i+1)*8])
			}
			buckets = append(buckets, bucketData{
				addr:   addr,
				size:   size,
				stk:    stk,
				active: active,
			})
		}

		addr = allnext
	}

	return buckets, nil
}

func buildProfiles(buckets []bucketData, resolve func(uint64) string, duration time.Duration, prev goHeapPrevState) ([]goHeapProfile, goHeapPrevState) {
	locMap := map[uint64]*profile.Location{}
	funcMap := map[string]*profile.Function{}
	samples := map[uint64]*sampleAcc{}
	var locID, funcID uint64

	for _, b := range buckets {
		locs := make([]*profile.Location, 0, len(b.stk))
		for _, pc := range b.stk {
			loc := locMap[pc]
			if loc == nil {
				locID++
				loc = &profile.Location{
					ID:      locID,
					Address: pc,
				}
				if resolve != nil {
					if name := resolve(pc); name != "" {
						fn := funcMap[name]
						if fn == nil {
							funcID++
							fn = &profile.Function{ID: funcID, Name: name}
							funcMap[name] = fn
						}
						loc.Line = []profile.Line{{Function: fn}}
					}
				}
				locMap[pc] = loc
			}
			locs = append(locs, loc)
		}

		s := samples[b.addr]
		if s == nil {
			s = &sampleAcc{locs: locs}
			samples[b.addr] = s
		}

		s.allocObjects += int64(b.active.Allocs)
		s.allocBytes += int64(b.active.AllocBytes)

		inuseObjects := int64(b.active.Allocs) - int64(b.active.Frees)
		inuseBytes := int64(b.active.AllocBytes) - int64(b.active.FreeBytes)
		if inuseObjects < 0 {
			inuseObjects = 0
		}
		if inuseBytes < 0 {
			inuseBytes = 0
		}
		s.inuseObjects += inuseObjects
		s.inuseBytes += inuseBytes
	}

	hasPrev := prev != nil
	curr := make(goHeapPrevState, len(samples))
	for key, s := range samples {
		curr[key] = prevValues{
			allocObjects: s.allocObjects,
			allocBytes:   s.allocBytes,
		}
		if hasPrev {
			p := prev[key]
			deltaObjects := s.allocObjects - p.allocObjects
			deltaBytes := s.allocBytes - p.allocBytes
			if deltaObjects < 0 {
				deltaObjects = s.allocObjects
			}
			if deltaBytes < 0 {
				deltaBytes = s.allocBytes
			}
			s.allocObjects = deltaObjects
			s.allocBytes = deltaBytes
		}
	}

	var allFuncs []*profile.Function
	for _, fn := range funcMap {
		allFuncs = append(allFuncs, fn)
	}

	now := time.Now().UnixNano()
	periodType := &profile.ValueType{Type: "space", Unit: "bytes"}
	var result []goHeapProfile

	if hasPrev {
		result = append(result,
			emitProfile(profileTypeAllocObjects, "count", periodType, allFuncs, samples, now, duration,
				func(s *sampleAcc) int64 { return s.allocObjects }),
			emitProfile(profileTypeAllocSpace, "bytes", periodType, allFuncs, samples, now, duration,
				func(s *sampleAcc) int64 { return s.allocBytes }),
		)
	}

	result = append(result,
		emitProfile(profileTypeInuseObjects, "count", periodType, allFuncs, samples, now, duration,
			func(s *sampleAcc) int64 { return s.inuseObjects }),
		emitProfile(profileTypeInuseSpace, "bytes", periodType, allFuncs, samples, now, duration,
			func(s *sampleAcc) int64 { return s.inuseBytes }),
	)

	return result, curr
}

func emitProfile(typeName, unit string, periodType *profile.ValueType,
	funcs []*profile.Function, samples map[uint64]*sampleAcc, timeNanos int64, duration time.Duration,
	valFn func(*sampleAcc) int64) goHeapProfile {

	prof := &profile.Profile{
		SampleType:    []*profile.ValueType{{Type: typeName, Unit: unit}},
		TimeNanos:     timeNanos,
		DurationNanos: duration.Nanoseconds(),
		PeriodType:    periodType,
		Function:      funcs,
	}

	seenLocs := map[uint64]bool{}
	for _, s := range samples {
		val := valFn(s)
		if val <= 0 {
			continue
		}
		prof.Sample = append(prof.Sample, &profile.Sample{
			Location: s.locs,
			Value:    []int64{val},
		})
		for _, loc := range s.locs {
			if !seenLocs[loc.ID] {
				seenLocs[loc.ID] = true
				prof.Location = append(prof.Location, loc)
			}
		}
	}

	return goHeapProfile{Type: typeName, Prof: prof}
}

func readUint64(f *os.File, addr uint64) (uint64, error) {
	buf := make([]byte, 8)
	if _, err := f.ReadAt(buf, int64(addr)); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf), nil
}
