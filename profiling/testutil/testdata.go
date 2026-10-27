package testutil

import (
	"os"
	"testing"
)

// RequireTestdata skips the test unless the large fixture tree (Python, glibc
// and musl binaries) is present at the given path. The fixtures live in
// https://github.com/coroot/pyroscope-ebpf-testdata and are not part of this
// repository. Clone them into profiling/testdata to run these tests.
func RequireTestdata(t testing.TB, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("testdata not found at %s: %v", path, err)
	}
}
