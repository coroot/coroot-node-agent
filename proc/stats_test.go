package proc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseStatus(t *testing.T) {
	s := parseStatus([]byte("Name:\tworker\nVmSize:\t  2048 kB\nVmData:\t  1024 kB\nVmRSS:\t 512 kB\nRssAnon:\t 256 kB\nRssFile:\t 128 kB\nRssShmem:\t 64 kB\nVmSwap:\t 8 kB\nThreads:\t7\nvoluntary_ctxt_switches:\t100\nnonvoluntary_ctxt_switches:\t5\n"))
	assert.Equal(t, 2048.*1024, s.VmSizeBytes)
	assert.Equal(t, 1024.*1024, s.VmDataBytes)
	assert.Equal(t, 512.*1024, s.RssBytes)
	assert.Equal(t, 256.*1024, s.RssAnonBytes)
	assert.Equal(t, 128.*1024, s.RssFileBytes)
	assert.Equal(t, 64.*1024, s.RssShmemBytes)
	assert.Equal(t, 8.*1024, s.VmSwapBytes)
	assert.Equal(t, 7., s.Threads)
	assert.Equal(t, 100., s.VoluntaryCtxSwitches)
	assert.Equal(t, 5., s.InvoluntaryCtxSwitch)
}

func TestParseFaults(t *testing.T) {
	minor, major := parseFaults([]byte("123 (my (odd) name) S 1 123 123 0 -1 4194560 3000 0 17 0 10 5 0 0 20 0 1 0 100 1000 100 18446744073709551615\n"))
	assert.Equal(t, 3000., minor)
	assert.Equal(t, 17., major)
}

func TestClassifyFd(t *testing.T) {
	cases := map[string]string{
		"socket:[1234]":                    "socket",
		"pipe:[99]":                        "pipe",
		"anon_inode:[eventfd]":             "eventfd",
		"anon_inode:[eventpoll]":           "epoll",
		"/dev/infiniband/uverbs0":          "uverbs",
		"/dev/infiniband/rdma_cm":          "rdma_cm",
		"/dev/nvidiactl":                   "nvidia",
		"/dev/shm/segment1":                "shm",
		"/dev/null":                        "device",
		"/var/log/app.log":                 "file",
		"anon_inode:[infiniband_verbs]":    "ib_event",
		"weird":                            "other",
		"anon_inode:[something-different]": "anon_other",
	}
	for in, want := range cases {
		assert.Equal(t, want, ClassifyFd(in), in)
	}
}

func TestReadFdStats(t *testing.T) {
	dir := t.TempDir()
	prev := root
	root = dir
	defer func() { root = prev }()

	fdDir := filepath.Join(dir, "42", "fd")
	assert.NoError(t, os.MkdirAll(fdDir, 0o755))
	for i, dest := range []string{"socket:[1]", "socket:[2]", "/dev/infiniband/rdma_cm", "/dev/infiniband/rdma_cm", "/dev/infiniband/uverbs0", "/tmp/x"} {
		assert.NoError(t, os.Symlink(dest, filepath.Join(fdDir, string(rune('0'+i)))))
	}
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "42", "limits"), []byte("Limit Soft Limit Hard Limit Units\nMax open files            1024                 4096                 files\n"), 0o644))

	s, err := ReadFdStats(42, 100)
	assert.NoError(t, err)
	assert.Equal(t, 6., s.Total)
	assert.Equal(t, 1024., s.Limit)
	assert.Equal(t, map[string]float64{"socket": 2, "rdma_cm": 2, "uverbs": 1, "file": 1}, s.ByKind)

	s, err = ReadFdStats(42, 3)
	assert.NoError(t, err)
	assert.Equal(t, map[string]float64{"unclassified": 6}, s.ByKind)

	_, err = ReadFdStats(43, 100)
	assert.Error(t, err)
}
