package logging

import (
	"flag"
	"io"
	"os"
	"strings"

	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

// Levels are the severities that Init routes, ordered from the lowest to the
// highest. FATAL is deliberately absent: -stderrthreshold below already writes
// fatals straight to stderr, so routing it here as well would write them twice.
var Levels = []string{"INFO", "WARNING", "ERROR"}

// Init makes klog write each message exactly once, and sends every severity
// below minLevel to io.Discard so that those messages are dropped before they
// reach out. It reports whether minLevel names a known severity; an unknown one
// leaves every severity enabled, so that the caller can report the error.
func Init(minLevel string, out io.Writer) bool {
	initKlog()
	return configureOutputs(minLevel, out)
}

// RateLimited returns a writer that drops messages once the caller exceeds
// perSecond lines, having consumed at most burst of them up front.
func RateLimited(perSecond float64, burst int) io.Writer {
	return &rateLimitedOutput{limiter: rate.NewLimiter(rate.Limit(perSecond), burst)}
}

// initKlog makes klog write each message exactly once. By default klog writes a
// message to the output of its own severity and to the output of every lower
// severity, and separately copies anything at or above -stderrthreshold (ERROR)
// straight to stderr, which would emit every warning twice and every error four
// times. Only fatals keep that stderr copy, un-throttled by design.
func initKlog() {
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	klog.InitFlags(fs)
	if err := fs.Parse([]string{"-one_output=true", "-stderrthreshold=FATAL"}); err != nil {
		klog.Exitln("failed to configure klog:", err)
	}
	klog.LogToStderr(false)
	// Fatals are already on stderr; discarding them here keeps klog from falling
	// back to writing them to a log file.
	klog.SetOutputBySeverity("FATAL", io.Discard)
}

func configureOutputs(minLevel string, out io.Writer) bool {
	minIdx, known := 0, false
	for i, level := range Levels {
		if strings.EqualFold(level, minLevel) {
			minIdx, known = i, true
			break
		}
	}
	for i, level := range Levels {
		if i < minIdx {
			klog.SetOutputBySeverity(level, io.Discard)
		} else {
			klog.SetOutputBySeverity(level, out)
		}
	}
	return known
}

type rateLimitedOutput struct {
	limiter *rate.Limiter
}

func (o *rateLimitedOutput) Write(data []byte) (int, error) {
	if !o.limiter.Allow() {
		return len(data), nil
	}
	return os.Stderr.Write(data)
}
