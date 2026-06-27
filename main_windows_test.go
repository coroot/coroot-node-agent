//go:build windows

package main

import "testing"

func TestWindowsUname(t *testing.T) {
	hostname, version, err := uname()
	if err != nil {
		t.Fatalf("uname failed: %v", err)
	}
	if hostname == "" {
		t.Fatal("hostname is empty")
	}
	if version == "" || version == "10.0.0" {
		t.Fatalf("expected concrete Windows version, got %q", version)
	}
}

func TestWindowsNodeInfoKernelVersionLabel(t *testing.T) {
	if got := nodeInfoKernelVersion("10.0.19045"); got != "Windows 10.0.19045" {
		t.Fatalf("nodeInfoKernelVersion() = %q, want %q", got, "Windows 10.0.19045")
	}
	if got := nodeInfoKernelVersion("Windows 10.0.19045"); got != "Windows 10.0.19045" {
		t.Fatalf("nodeInfoKernelVersion() should not double-prefix Windows versions, got %q", got)
	}
}
