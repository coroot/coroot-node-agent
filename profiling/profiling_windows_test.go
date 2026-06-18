//go:build windows

package profiling

import "testing"

func TestWindowsProfilingNoopContract(t *testing.T) {
	processInfoCh, updateCh := Init("host-id", "host-name")
	if processInfoCh != nil {
		t.Fatal("Windows profiling should not consume process info until a profiler source is implemented")
	}
	if updateCh == nil {
		t.Fatal("Windows profiling must return a non-nil update channel")
	}
	Start()
	Stop()
}
