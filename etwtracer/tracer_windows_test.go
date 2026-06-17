//go:build windows

package etwtracer

import "testing"

func TestParseKernelNetworkEvent(t *testing.T) {
	e := NewTestEvent(10, map[string]interface{}{
		"PID":     "1234",
		"size":    "42",
		"saddr":   "10.0.0.2",
		"sport":   "50000",
		"daddr":   "93.184.216.34",
		"dport":   "80",
		"connid":  "99",
		"ignored": "value",
	})
	event, ok := ParseKernelNetworkEvent(e)
	if !ok {
		t.Fatal("expected event to parse")
	}
	if event.Type != EventTypeTCPDataSent {
		t.Fatalf("unexpected type: %v", event.Type)
	}
	if event.Pid != 1234 || event.Bytes != 42 || event.ConnID != "99" {
		t.Fatalf("unexpected event fields: %+v", event)
	}
	if got := event.Src.String(); got != "10.0.0.2:50000" {
		t.Fatalf("unexpected src: %s", got)
	}
	if got := event.Dst.String(); got != "93.184.216.34:80" {
		t.Fatalf("unexpected dst: %s", got)
	}
}

func TestParseKernelNetworkEventSkipsUnknownEventID(t *testing.T) {
	if _, ok := ParseKernelNetworkEvent(NewTestEvent(42, map[string]interface{}{"PID": "1234"})); ok {
		t.Fatal("expected UDP event to be skipped")
	}
}
