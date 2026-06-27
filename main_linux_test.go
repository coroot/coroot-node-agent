//go:build linux

package main

import "testing"

func TestLinuxNodeInfoKernelVersionLabel(t *testing.T) {
	if got := nodeInfoKernelVersion("6.8.0-63-generic"); got != "6.8.0-63-generic" {
		t.Fatalf("nodeInfoKernelVersion() = %q, want unchanged Linux kernel version", got)
	}
}
