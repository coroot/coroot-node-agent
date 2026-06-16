//go:build windows

package node

import (
	"net"
	"testing"
)

func TestWindowsUptime(t *testing.T) {
	v, err := uptime("")
	if err != nil {
		t.Fatalf("uptime failed: %v", err)
	}
	if v <= 0 {
		t.Fatalf("expected positive uptime, got %f", v)
	}
}

func TestWindowsCPUStat(t *testing.T) {
	stat, err := cpuStat("")
	if err != nil {
		t.Fatalf("cpuStat failed: %v", err)
	}
	if stat.LogicalCores <= 0 {
		t.Fatalf("expected at least one logical core, got %d", stat.LogicalCores)
	}
	if stat.TotalUsage.User <= 0 && stat.TotalUsage.System <= 0 && stat.TotalUsage.Idle <= 0 {
		t.Fatalf("expected non-zero CPU times, got %+v", stat.TotalUsage)
	}
}

func TestWindowsMemoryInfo(t *testing.T) {
	stat, err := memoryInfo("")
	if err != nil {
		t.Fatalf("memoryInfo failed: %v", err)
	}
	if stat.TotalBytes <= 0 {
		t.Fatalf("expected positive total memory, got %f", stat.TotalBytes)
	}
	if stat.AvailableBytes < 0 || stat.FreeBytes < 0 {
		t.Fatalf("expected non-negative available memory, got %+v", stat)
	}
	if stat.AvailableBytes > stat.TotalBytes {
		t.Fatalf("available memory exceeds total memory: %+v", stat)
	}
}

func TestWindowsDisks(t *testing.T) {
	disks, err := GetDisks()
	if err != nil {
		t.Fatalf("GetDisks failed: %v", err)
	}
	for _, disk := range disks.BlockDevices() {
		if disk.Name == "" {
			t.Fatalf("disk name is empty: %+v", disk)
		}
		if disk.ReadOps < 0 || disk.WriteOps < 0 || disk.BytesRead < 0 || disk.BytesWritten < 0 {
			t.Fatalf("disk counters must be non-negative: %+v", disk)
		}
	}
}

func TestWindowsNetDevices(t *testing.T) {
	devices, err := NetDevices()
	if err != nil {
		t.Fatalf("NetDevices failed: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("expected at least one non-loopback interface")
	}
	for _, dev := range devices {
		if dev.Name == "" {
			t.Fatalf("interface name is empty: %+v", dev)
		}
		if dev.RxBytes < 0 || dev.TxBytes < 0 || dev.RxPackets < 0 || dev.TxPackets < 0 {
			t.Fatalf("network counters must be non-negative: %+v", dev)
		}
	}
}

func TestSkipInterfaceIP(t *testing.T) {
	cases := []struct {
		name string
		ip   net.IP
		skip bool
	}{
		{name: "nil", ip: nil, skip: true},
		{name: "unspecified", ip: net.ParseIP("0.0.0.0"), skip: true},
		{name: "loopback", ip: net.ParseIP("127.0.0.1"), skip: true},
		{name: "link local", ip: net.ParseIP("169.254.1.1"), skip: true},
		{name: "multicast", ip: net.ParseIP("224.0.0.1"), skip: true},
		{name: "private", ip: net.ParseIP("10.0.0.1"), skip: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := skipInterfaceIP(tc.ip); got != tc.skip {
				t.Fatalf("skipInterfaceIP(%v)=%v, want %v", tc.ip, got, tc.skip)
			}
		})
	}
}
