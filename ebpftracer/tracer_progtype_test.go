package ebpftracer

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestCheckProgramTypes(t *testing.T) {
	orig := haveProgramType
	defer func() { haveProgramType = orig }()

	t.Run("supported", func(t *testing.T) {
		haveProgramType = func(ebpf.ProgramType) error { return nil }
		assert.NoError(t, checkProgramTypes())
	})

	t.Run("not supported", func(t *testing.T) {
		// Shaped like the *ebpf.UnsupportedFeatureError returned by features.HaveProgramType.
		haveProgramType = func(pt ebpf.ProgramType) error {
			if pt == ebpf.Kprobe {
				return fmt.Errorf("Kprobe not supported (requires >= v4.1): %w", ebpf.ErrNotSupported)
			}
			return nil
		}
		err := checkProgramTypes()
		require.Error(t, err)
		assert.ErrorIs(t, err, ebpf.ErrNotSupported)
		assert.EqualError(t, err, "kernel does not support BPF Kprobe programs (CONFIG_BPF_EVENTS is not set?): not supported")
	})

	t.Run("inconclusive probe", func(t *testing.T) {
		haveProgramType = func(ebpf.ProgramType) error { return unix.EPERM }
		assert.NoError(t, checkProgramTypes())
	})
}
