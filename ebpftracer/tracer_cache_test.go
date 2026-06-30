package ebpftracer

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestTracer() *Tracer {
	return &Tracer{
		globalUprobes:   map[UprobeKey]*globalUprobe{},
		negativeUprobes: map[UprobeKey]negativeUprobe{},
		now:             time.Now,
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bin")
	require.NoError(t, os.WriteFile(p, []byte(content), 0755))
	return p
}

// A binary with nothing to instrument must be parsed once and then served from
// the cache, instead of being re-opened for every process that runs it.
func TestAcquireGlobalUprobeCachesEmptyResult(t *testing.T) {
	tr := newTestTracer()
	path := writeFile(t, "binary")

	calls := 0
	attach := func() []link.Link { calls++; return nil }

	for i := 0; i < 5; i++ {
		key, ok := tr.AcquireGlobalUprobe(path, attach)
		assert.False(t, ok)
		assert.Equal(t, UprobeKey{}, key)
	}
	assert.Equal(t, 1, calls, "attach must be called only once for an unchanged binary")
}

// A replaced binary (different size/mtime) must be evaluated again rather than
// reusing a stale negative result.
func TestAcquireGlobalUprobeReevaluatesReplacedBinary(t *testing.T) {
	tr := newTestTracer()
	path := writeFile(t, "v1")

	calls := 0
	attach := func() []link.Link { calls++; return nil }

	_, ok := tr.AcquireGlobalUprobe(path, attach)
	require.False(t, ok)
	require.Equal(t, 1, calls)

	require.NoError(t, os.WriteFile(path, []byte("v2-longer"), 0755))
	_, ok = tr.AcquireGlobalUprobe(path, attach)
	require.False(t, ok)
	assert.Equal(t, 2, calls, "a replaced binary must be re-evaluated")
}

// A binary repeatedly overwritten in place keeps the same inode, so the negative
// cache must hold exactly one entry, not one per spawn.
func TestNegativeCacheDoesNotGrowOnInPlaceOverwrite(t *testing.T) {
	tr := newTestTracer()
	path := writeFile(t, "v1")
	attach := func() []link.Link { return nil }

	for i := 0; i < 20; i++ {
		require.NoError(t, os.WriteFile(path, []byte("v"+strconv.Itoa(i)), 0755))
		_, ok := tr.AcquireGlobalUprobe(path, attach)
		require.False(t, ok)
	}
	assert.Len(t, tr.negativeUprobes, 1, "in-place overwrite must reuse one inode-keyed slot")
}

// An expired negative entry must be re-evaluated and replaced, not duplicated.
// Expiry is driven by an injected clock rather than by poking internals.
func TestAcquireGlobalUprobeExpiresEmptyResult(t *testing.T) {
	tr := newTestTracer()
	clock := time.Unix(0, 0)
	tr.now = func() time.Time { return clock }
	path := writeFile(t, "binary")

	calls := 0
	attach := func() []link.Link { calls++; return nil }

	_, ok := tr.AcquireGlobalUprobe(path, attach)
	require.False(t, ok)
	require.Equal(t, 1, calls)
	require.Len(t, tr.negativeUprobes, 1)

	clock = clock.Add(negativeUprobeCacheTTL + time.Second)
	_, ok = tr.AcquireGlobalUprobe(path, attach)
	require.False(t, ok)
	assert.Equal(t, 2, calls, "an expired negative entry must be re-evaluated")
	assert.Len(t, tr.negativeUprobes, 1, "the stale entry must be replaced, not duplicated")
}

// Expired negative entries must not accumulate; they are swept when a new
// negative entry is added (at most once per TTL).
func TestNegativeCacheSweepsExpiredEntries(t *testing.T) {
	tr := newTestTracer()
	clock := time.Unix(0, 0)
	tr.now = func() time.Time { return clock }

	for i := 0; i < 10; i++ {
		tr.negativeUprobes[UprobeKey{Ino: uint64(i + 1)}] = negativeUprobe{
			expiresAt: clock.Add(time.Minute),
		}
	}
	// A live (refcounted) entry must be untouched by the negative-cache sweep.
	tr.globalUprobes[UprobeKey{Ino: 100}] = &globalUprobe{refcount: 1}

	clock = clock.Add(negativeUprobeCacheTTL + time.Minute)
	_, ok := tr.AcquireGlobalUprobe(writeFile(t, "binary"), func() []link.Link { return nil })
	require.False(t, ok)

	assert.Len(t, tr.negativeUprobes, 1, "expired negative entries must be swept; only the fresh one remains")
	require.Len(t, tr.globalUprobes, 1, "live entries must be kept")
	_, live := tr.globalUprobes[UprobeKey{Ino: 100}]
	assert.True(t, live)
}

// The race detector must stay clean under concurrent acquisition of the same
// binary, and the result must be a single negative entry.
func TestNegativeCacheConcurrent(t *testing.T) {
	tr := newTestTracer()
	path := writeFile(t, "binary")
	attach := func() []link.Link { return nil }

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.AcquireGlobalUprobe(path, attach)
		}()
	}
	wg.Wait()
	assert.Len(t, tr.negativeUprobes, 1)
}
