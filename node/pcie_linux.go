package node

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// PCI base classes and sub-classes that matter for data path analysis: NVMe (0x0108), network and InfiniBand (0x02),
// display, GPU and 3D controllers (0x03).
var pcieClassPrefixes = []string{"0x0108", "0x02", "0x03"}

var pcieSpeed = regexp.MustCompile(`^([0-9.]+)\s*GT/s`)

var pcieAerFiles = map[string]string{
	"aer_dev_correctable": "correctable",
	"aer_dev_nonfatal":    "nonfatal",
	"aer_dev_fatal":       "fatal",
}

type PcieDevice struct {
	Address   string
	Class     string
	Vendor    string
	Device    string
	Driver    string
	NumaNode  string
	Speed     float64 // GT/s, 0 if unknown
	MaxSpeed  float64
	Width     float64 // lanes, 0 if unknown
	MaxWidth  float64
	AerErrors map[string]map[string]float64 // severity -> error -> count
}

// Degraded reports whether the link trained below the width the device supports, or below its speed. GPUs lower the
// link speed when idle to save power, so only their width is judged.
func (d PcieDevice) Degraded() bool {
	if d.Width > 0 && d.MaxWidth > 0 && d.Width < d.MaxWidth {
		return true
	}
	return !strings.HasPrefix(d.Class, "0x03") && d.Speed > 0 && d.MaxSpeed > 0 && d.Speed < d.MaxSpeed
}

// pcieDevices reads /sys/bus/pci/devices for the physical functions of the interesting classes. Virtual functions
// (they have a physfn link) are skipped because their link attributes describe the parent.
func pcieDevices(sysRoot string) []PcieDevice {
	root := filepath.Join(sysRoot, "bus", "pci", "devices")
	var res []PcieDevice
	for _, addr := range listDir(root) {
		dir := filepath.Join(root, addr)
		class, ok := readTrimmed(filepath.Join(dir, "class"))
		if !ok || !pcieClassWanted(class) || pathExists(filepath.Join(dir, "physfn")) {
			continue
		}
		d := PcieDevice{Address: addr, Class: class, Driver: linkBase(filepath.Join(dir, "driver"))}
		d.Vendor, _ = readTrimmed(filepath.Join(dir, "vendor"))
		d.Device, _ = readTrimmed(filepath.Join(dir, "device"))
		d.NumaNode, _ = readTrimmed(filepath.Join(dir, "numa_node"))
		d.Speed = parsePcieSpeed(dir, "current_link_speed")
		d.MaxSpeed = parsePcieSpeed(dir, "max_link_speed")
		d.Width, _ = readFloat(filepath.Join(dir, "current_link_width"))
		d.MaxWidth, _ = readFloat(filepath.Join(dir, "max_link_width"))
		d.AerErrors = map[string]map[string]float64{}
		for file, severity := range pcieAerFiles {
			if errs := readAer(filepath.Join(dir, file)); len(errs) > 0 {
				d.AerErrors[severity] = errs
			}
		}
		res = append(res, d)
	}
	return res
}

func pcieClassWanted(class string) bool {
	for _, p := range pcieClassPrefixes {
		if strings.HasPrefix(class, p) {
			return true
		}
	}
	return false
}

func parsePcieSpeed(dir, file string) float64 {
	s, ok := readTrimmed(filepath.Join(dir, file))
	if !ok {
		return 0
	}
	m := pcieSpeed.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v
}

// readAer parses the "Name count" lines of an aer_dev_* file; names are lower-cased ("RxErr" -> "rxerr",
// "TOTAL_ERR_COR" -> "total_err_cor").
func readAer(path string) map[string]float64 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	res := map[string]float64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		res[strings.ToLower(fields[0])] = v
	}
	return res
}
