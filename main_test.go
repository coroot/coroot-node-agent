package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"
)

// severityCounter records the severity letter klog puts at the start of every line.
type severityCounter struct {
	severities []byte
}

func (c *severityCounter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		c.severities = append(c.severities, p[0])
	}
	return len(p), nil
}

func (c *severityCounter) count(severity byte) int {
	n := 0
	for _, s := range c.severities {
		if s == severity {
			n++
		}
	}
	return n
}

func TestConfigureLogOutputs(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		minLevel                string
		known                   bool
		infos, warnings, errors int
	}{
		{name: "info", minLevel: "info", known: true, infos: 1, warnings: 1, errors: 1},
		{name: "warning", minLevel: "warning", known: true, infos: 0, warnings: 1, errors: 1},
		{name: "error", minLevel: "error", known: true, infos: 0, warnings: 0, errors: 1},
		{name: "upper case", minLevel: "ERROR", known: true, infos: 0, warnings: 0, errors: 1},
		{name: "mixed case", minLevel: "Warning", known: true, infos: 0, warnings: 1, errors: 1},
		// An unrecognized level must leave logging on, so that the caller can
		// report the error.
		{name: "unrecognized", minLevel: "nonsense", known: false, infos: 1, warnings: 1, errors: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initKlog()
			c := &severityCounter{}

			assert.Equal(t, tc.known, configureLogOutputs(tc.minLevel, c))

			klog.Info("info message")
			klog.Warning("warning message")
			klog.Error("error message")
			klog.Flush()

			// Each message must be written exactly once: without one_output klog
			// writes to every lower severity output too.
			assert.Equal(t, tc.infos, c.count('I'), "infos")
			assert.Equal(t, tc.warnings, c.count('W'), "warnings")
			assert.Equal(t, tc.errors, c.count('E'), "errors")
		})
	}
}

// Nothing may reach stderr twice: klog copies everything at or above
// -stderrthreshold there on top of the severity output, so only fatals may take
// that path. klog.Fatal exits the process, so the emitting half runs in a
// subprocess, whose stderr the parent counts.
func TestStderrIsNotDuplicated(t *testing.T) {
	const errorMarker = "error-marker-9c1f"
	const fatalMarker = "fatal-marker-9c1f"

	if os.Getenv("COROOT_TEST_FATAL") == "1" {
		initKlog()
		configureLogOutputs("info", os.Stderr)
		klog.Error(errorMarker)
		klog.Fatal(fatalMarker)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestStderrIsNotDuplicated")
	cmd.Env = append(os.Environ(), "COROOT_TEST_FATAL=1")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "subprocess unexpectedly exited without error, output:\n%s", out)

	assert.Equal(t, 1, strings.Count(string(out), errorMarker), "output:\n%s", out)
	assert.Equal(t, 1, strings.Count(string(out), fatalMarker), "output:\n%s", out)
}
