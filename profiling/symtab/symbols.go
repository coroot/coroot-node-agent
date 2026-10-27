package symtab

import (
	"fmt"

	"k8s.io/klog/v2"
)

type PidKey uint32

// SymbolCache is responsible for resolving PC address to Symbol
// maintaining a pid -> ProcTable cache
// resolving kernel symbols
type SymbolCache struct {
	pidCache *GCache[PidKey, *ProcTable]

	elfCache *ElfCache
	kallsyms *SymbolTab
}
type CacheOptions struct {
	PidCacheOptions      GCacheOptions
	BuildIDCacheOptions  GCacheOptions
	SameFileCacheOptions GCacheOptions
}

func NewSymbolCache(options CacheOptions) (*SymbolCache, error) {
	elfCache, err := NewElfCache(options.BuildIDCacheOptions, options.SameFileCacheOptions)
	if err != nil {
		return nil, fmt.Errorf("create elf cache %w", err)
	}

	cache, err := NewGCache[PidKey, *ProcTable](options.PidCacheOptions)
	if err != nil {
		return nil, fmt.Errorf("create pid cache %w", err)
	}
	return &SymbolCache{
		pidCache: cache,
		kallsyms: nil,
		elfCache: elfCache,
	}, nil
}

func (sc *SymbolCache) NextRound() {
	sc.pidCache.NextRound()
	sc.elfCache.NextRound()
}

func (sc *SymbolCache) Cleanup() {
	sc.elfCache.Cleanup()
	sc.pidCache.Cleanup()
}

func (sc *SymbolCache) GetProcTableCached(pid PidKey) *ProcTable {
	cached := sc.pidCache.Get(pid)
	if cached != nil {
		return cached
	}
	return nil
}

func (sc *SymbolCache) NewProcTable(pid PidKey, symbolOptions *SymbolOptions) *ProcTable {
	fresh := NewProcTable(ProcTableOptions{
		Pid: int(pid),
		ElfTableOptions: ElfTableOptions{
			ElfCache:      sc.elfCache,
			SymbolOptions: symbolOptions,
		},
	})

	sc.pidCache.Cache(pid, fresh)
	return fresh
}

func (sc *SymbolCache) GetKallsyms() SymbolTable {
	if sc.kallsyms != nil {
		return sc.kallsyms
	}
	return sc.initKallsyms()
}

func (sc *SymbolCache) initKallsyms() SymbolTable {
	var err error
	sc.kallsyms, err = NewKallsyms()
	if err != nil {
		klog.Errorf("kallsyms init failed: %v", err)
		sc.kallsyms = NewSymbolTab(nil)
	}
	if len(sc.kallsyms.symbols) == 0 {
		klog.Errorln("kallsyms is empty: check kptr_restrict and perf_event_paranoid or CAP_SYSLOG")
	}

	return sc.kallsyms
}

func (sc *SymbolCache) UpdateOptions(options CacheOptions) {
	sc.pidCache.Update(options.PidCacheOptions)
	sc.elfCache.Update(options.BuildIDCacheOptions, options.SameFileCacheOptions)
}

func (sc *SymbolCache) RemoveDeadPID(pid PidKey) {
	sc.pidCache.Remove(pid)
}
