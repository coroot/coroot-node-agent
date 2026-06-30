package ebpftracer

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"
)

func buildGoBinary(t *testing.T, ldflags string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0644))
	bin := filepath.Join(dir, "app")
	args := []string{"build", "-o", bin}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, src)
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return bin
}

// Stripped binaries (e.g. kubectl built with -s -w) carry no symbol table, so
// Go TLS uprobes can't be attached. This must be treated as a silent condition
// rather than spamming an error for every such process.
func TestGetSymbolStrippedBinary(t *testing.T) {
	ef, err := OpenELFFile(buildGoBinary(t, "-s -w"))
	require.NoError(t, err)
	defer ef.Close()

	_, err = ef.GetSymbol(goTlsWriteSymbol)
	require.Error(t, err)
	assert.Equal(t, "no symbols found", err.Error())
	assert.True(t, isSilentError(err), "stripped binary error must be silenced")
}

func captureKlog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	require.NoError(t, fs.Set("logtostderr", "false"))
	require.NoError(t, fs.Set("stderrthreshold", "FATAL"))
	klog.SetOutput(&buf)
	defer func() {
		klog.Flush()
		_ = fs.Set("logtostderr", "true")
		klog.SetOutput(nil)
	}()
	fn()
	klog.Flush()
	return buf.String()
}

func TestUprobeLogSilentError(t *testing.T) {
	out := captureKlog(t, func() {
		uprobeLog(1, "")("failed to get symbol "+goTlsWriteSymbol, errors.New("no symbols found"))
	})
	assert.Empty(t, out)
}

func TestUprobeLogReportsRealError(t *testing.T) {
	out := captureKlog(t, func() {
		uprobeLog(1, "")("failed to attach uprobe", errors.New("operation not permitted"))
	})
	assert.Contains(t, out, "failed to attach uprobe")
}
