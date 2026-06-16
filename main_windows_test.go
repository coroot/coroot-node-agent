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
