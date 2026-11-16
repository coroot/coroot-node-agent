package node

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Linux reports the data counters of an InfiniBand/RoCE port in units of 4 bytes (one octet per lane).
const rdmaDataCounterUnit = 4

var (
	rdmaRate       = regexp.MustCompile(`^([0-9.]+)\s*([GMK]?)b/sec`)
	rdmaDataCounts = map[string]string{"port_rcv_data": "rx", "port_xmit_data": "tx"}
)

type RdmaPort struct {
	Number            string
	State             float64
	PhysState         float64
	LinkLayer         string
	RateBitsPerSecond float64
	RxBytes           float64
	TxBytes           float64
	HasDataCounters   bool
	Counters          map[string]float64
	HwCounters        map[string]float64
}

type RdmaDevice struct {
	Name       string
	PciAddress string
	Netdev     string
	FwVersion  string
	Ports      []RdmaPort
}

// rdmaDevices reads /sys/class/infiniband: per device the firmware, PCI address and net device, per port the
// state, link layer, rate, standard port counters and the vendor specific hw_counters.
func rdmaDevices(sysRoot string) []RdmaDevice {
	root := filepath.Join(sysRoot, "class", "infiniband")
	var res []RdmaDevice
	for _, name := range listDir(root) {
		dir := filepath.Join(root, name)
		dev := RdmaDevice{Name: name, PciAddress: linkBase(filepath.Join(dir, "device"))}
		dev.FwVersion, _ = readTrimmed(filepath.Join(dir, "fw_ver"))
		for _, port := range listDir(filepath.Join(dir, "ports")) {
			p := readRdmaPort(filepath.Join(dir, "ports", port), port)
			if dev.Netdev == "" {
				dev.Netdev, _ = readTrimmed(filepath.Join(dir, "ports", port, "gid_attrs", "ndevs", "0"))
			}
			dev.Ports = append(dev.Ports, p)
		}
		res = append(res, dev)
	}
	return res
}

func readRdmaPort(dir, number string) RdmaPort {
	p := RdmaPort{Number: number, Counters: map[string]float64{}, HwCounters: map[string]float64{}}
	if s, ok := readTrimmed(filepath.Join(dir, "state")); ok {
		p.State, _ = leadingNumber(s)
	}
	if s, ok := readTrimmed(filepath.Join(dir, "phys_state")); ok {
		p.PhysState, _ = leadingNumber(s)
	}
	p.LinkLayer, _ = readTrimmed(filepath.Join(dir, "link_layer"))
	if s, ok := readTrimmed(filepath.Join(dir, "rate")); ok {
		p.RateBitsPerSecond = parseRdmaRate(s)
	}
	for _, name := range listDir(filepath.Join(dir, "counters")) {
		v, ok := readFloat(filepath.Join(dir, "counters", name))
		if !ok {
			continue
		}
		switch rdmaDataCounts[name] {
		case "rx":
			p.RxBytes = v * rdmaDataCounterUnit
			p.HasDataCounters = true
		case "tx":
			p.TxBytes = v * rdmaDataCounterUnit
			p.HasDataCounters = true
		default:
			p.Counters[name] = v
		}
	}
	for _, name := range listDir(filepath.Join(dir, "hw_counters")) {
		if name == "lifespan" { // the sampling period of the driver, not a counter
			continue
		}
		if v, ok := readFloat(filepath.Join(dir, "hw_counters", name)); ok {
			p.HwCounters[name] = v
		}
	}
	return p
}

// parseRdmaRate converts "100 Gb/sec (4X EDR)" to bits per second.
func parseRdmaRate(s string) float64 {
	m := rdmaRate.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	switch m[2] {
	case "G":
		v *= 1e9
	case "M":
		v *= 1e6
	case "K":
		v *= 1e3
	}
	return v
}
