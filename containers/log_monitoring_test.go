package containers

import (
	"testing"

	"github.com/coroot/coroot-node-agent/proc"
)

func TestLogMonitoringDisabledRequiresRegisteredProcess(t *testing.T) {
	empty := &Container{processes: map[uint32]*Process{}}
	if empty.logMonitoringDisabled() {
		t.Fatal("empty process map must not skip log monitoring")
	}

	flagged := &Container{processes: map[uint32]*Process{
		1: {Flags: proc.Flags{LogMonitoringDisabled: true}},
	}}
	if !flagged.logMonitoringDisabled() {
		t.Fatal("COROOT_LOG_MONITORING=disabled on a registered process must skip log monitoring")
	}

	enabled := &Container{processes: map[uint32]*Process{
		1: {Flags: proc.Flags{}},
	}}
	if enabled.logMonitoringDisabled() {
		t.Fatal("process without the flag must not skip log monitoring")
	}
}
