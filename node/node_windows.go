//go:build windows

package node

import (
	"os"

	"inet.af/netaddr"
)

func uptime(procRoot string) (float64, error) {
	return 0, os.ErrNotExist
}

func cpuStat(procRoot string) (CpuStat, error) {
	return CpuStat{}, os.ErrNotExist
}

func memoryInfo(procRoot string) (MemoryStat, error) {
	return MemoryStat{}, os.ErrNotExist
}

type DevStat struct {
	Name             string
	MajorMinor       string
	ReadOps          float64
	WriteOps         float64
	BytesRead        float64
	BytesWritten     float64
	ReadTimeSeconds  float64
	WriteTimeSeconds float64
	IoTimeSeconds    float64
}

type Disks struct{}

func (disks *Disks) BlockDevices() []DevStat {
	return nil
}

func (disks *Disks) GetParentBlockDevice(majorMinor string) *DevStat {
	return nil
}

func GetDisks() (*Disks, error) {
	return &Disks{}, nil
}

type NetDeviceInfo struct {
	Name       string
	Up         float64
	IPPrefixes []netaddr.IPPrefix
	RxBytes    float64
	TxBytes    float64
	RxPackets  float64
	TxPackets  float64
}

func NetDevices() ([]NetDeviceInfo, error) {
	return nil, nil
}
