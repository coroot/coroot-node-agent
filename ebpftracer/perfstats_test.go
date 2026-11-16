package ebpftracer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetPerfOptions(t *testing.T) {
	tr := NewTracer(0, 0, false)
	assert.Equal(t, DefaultPerfOptions(), tr.perfOptions)

	tr.SetPerfOptions(PerfOptions{L7EventsBufferPages: 128, WakeupEvents: 16})
	assert.Equal(t, PerfOptions{L7EventsBufferPages: 128, WakeupEvents: 16}, tr.perfOptions)

	tr.SetPerfOptions(PerfOptions{})
	assert.Equal(t, DefaultPerfOptions(), tr.perfOptions)
}

func TestPerfStats(t *testing.T) {
	tr := NewTracer(0, 0, false)
	assert.Empty(t, tr.PerfStats())

	s := &perfMapStats{name: "l7_events", bufferBytes: 131072}
	tr.perfStats = append(tr.perfStats, s)
	s.events.Add(5)
	s.lost.Add(7)
	assert.Equal(t, []PerfMapStats{{Name: "l7_events", BufferBytes: 131072, Events: 5, LostSamples: 7}}, tr.PerfStats())
}
