package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	assert.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	assert.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func link(t *testing.T, root, rel, target string) {
	t.Helper()
	p := filepath.Join(root, rel)
	assert.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	assert.NoError(t, os.Symlink(target, p))
}

func fakeSys(t *testing.T) string {
	root := t.TempDir()

	ib := "class/infiniband/mlx5_0/"
	write(t, root, ib+"fw_ver", "22.36.1010\n")
	link(t, root, ib+"device", "../../../0000:3b:00.0")
	write(t, root, ib+"ports/1/state", "4: ACTIVE\n")
	write(t, root, ib+"ports/1/phys_state", "5: LinkUp\n")
	write(t, root, ib+"ports/1/link_layer", "Ethernet\n")
	write(t, root, ib+"ports/1/rate", "200 Gb/sec (2X HDR)\n")
	write(t, root, ib+"ports/1/gid_attrs/ndevs/0", "ens1f0\n")
	write(t, root, ib+"ports/1/counters/port_rcv_data", "1000\n")
	write(t, root, ib+"ports/1/counters/port_xmit_data", "500\n")
	write(t, root, ib+"ports/1/counters/symbol_error", "3\n")
	write(t, root, ib+"ports/1/counters/link_downed", "1\n")
	write(t, root, ib+"ports/1/counters/not_a_number", "x\n")
	write(t, root, ib+"ports/1/hw_counters/out_of_sequence", "7\n")
	write(t, root, ib+"ports/1/hw_counters/np_cnp_sent", "9\n")
	write(t, root, ib+"ports/1/hw_counters/lifespan", "10\n")

	pci := "bus/pci/devices/"
	write(t, root, pci+"0000:41:00.0/class", "0x030200\n")
	write(t, root, pci+"0000:41:00.0/vendor", "0x10de\n")
	write(t, root, pci+"0000:41:00.0/device", "0x2704\n")
	write(t, root, pci+"0000:41:00.0/numa_node", "1\n")
	write(t, root, pci+"0000:41:00.0/current_link_speed", "16.0 GT/s PCIe\n")
	write(t, root, pci+"0000:41:00.0/max_link_speed", "16.0 GT/s PCIe\n")
	write(t, root, pci+"0000:41:00.0/current_link_width", "8\n")
	write(t, root, pci+"0000:41:00.0/max_link_width", "16\n")
	link(t, root, pci+"0000:41:00.0/driver", "../../../../bus/pci/drivers/nvidia")
	write(t, root, pci+"0000:41:00.0/aer_dev_correctable", "RxErr 2\nBadTLP 0\nTOTAL_ERR_COR 2\n")
	write(t, root, pci+"0000:41:00.0/aer_dev_fatal", "Undefined 0\nTOTAL_ERR_FATAL 0\n")

	write(t, root, pci+"0000:3b:00.0/class", "0x020700\n")
	write(t, root, pci+"0000:3b:00.0/vendor", "0x15b3\n")
	write(t, root, pci+"0000:3b:00.0/device", "0x101d\n")
	write(t, root, pci+"0000:3b:00.0/numa_node", "0\n")
	write(t, root, pci+"0000:3b:00.0/current_link_speed", "16.0 GT/s PCIe\n")
	write(t, root, pci+"0000:3b:00.0/max_link_speed", "16.0 GT/s PCIe\n")
	write(t, root, pci+"0000:3b:00.0/current_link_width", "16\n")
	write(t, root, pci+"0000:3b:00.0/max_link_width", "16\n")
	link(t, root, pci+"0000:3b:00.0/driver", "../../../../bus/pci/drivers/mlx5_core")

	write(t, root, pci+"0000:3b:00.2/class", "0x020000\n") // virtual function
	link(t, root, pci+"0000:3b:00.2/physfn", "../0000:3b:00.0")
	write(t, root, pci+"0000:00:1c.0/class", "0x060400\n") // bridge

	write(t, root, pci+"0000:5e:00.0/class", "0x010802\n") // NVMe, link speed not exposed
	write(t, root, pci+"0000:5e:00.0/current_link_speed", "Unknown\n")
	return root
}

func TestRdmaDevices(t *testing.T) {
	devs := rdmaDevices(fakeSys(t))
	assert.Len(t, devs, 1)
	d := devs[0]
	assert.Equal(t, "mlx5_0", d.Name)
	assert.Equal(t, "0000:3b:00.0", d.PciAddress)
	assert.Equal(t, "ens1f0", d.Netdev)
	assert.Equal(t, "22.36.1010", d.FwVersion)
	assert.Len(t, d.Ports, 1)
	p := d.Ports[0]
	assert.Equal(t, "1", p.Number)
	assert.Equal(t, 4., p.State)
	assert.Equal(t, 5., p.PhysState)
	assert.Equal(t, "Ethernet", p.LinkLayer)
	assert.Equal(t, 200e9, p.RateBitsPerSecond)
	assert.Equal(t, 4000., p.RxBytes)
	assert.Equal(t, 2000., p.TxBytes)
	assert.Equal(t, map[string]float64{"symbol_error": 3, "link_downed": 1}, p.Counters)
	assert.Equal(t, map[string]float64{"out_of_sequence": 7, "np_cnp_sent": 9}, p.HwCounters)
}

func TestRdmaPortWithoutCounters(t *testing.T) {
	root := t.TempDir()
	write(t, root, "class/infiniband/mlx5_9/ports/1/state", "4: ACTIVE\n")
	devs := rdmaDevices(root)
	assert.Len(t, devs, 1)
	assert.False(t, devs[0].Ports[0].HasDataCounters)
	c := &Collector{SysfsRoot: root}
	ch := make(chan prometheus.Metric, 50)
	c.collectRdma(ch)
	close(ch)
	n := 0
	for range ch {
		n++
	}
	assert.Equal(t, 1, n) // device info only
}

func TestRdmaDevicesAbsent(t *testing.T) {
	assert.Empty(t, rdmaDevices(t.TempDir()))
}

func TestParseRdmaRate(t *testing.T) {
	assert.Equal(t, 100e9, parseRdmaRate("100 Gb/sec (4X EDR)"))
	assert.Equal(t, 2.5e9, parseRdmaRate("2.5 Gb/sec (1X SDR)"))
	assert.Equal(t, 100e6, parseRdmaRate("100 Mb/sec"))
	assert.Equal(t, 0., parseRdmaRate("garbage"))
}

func TestPcieDevices(t *testing.T) {
	devs := pcieDevices(fakeSys(t))
	var addrs []string
	byAddr := map[string]PcieDevice{}
	for _, d := range devs {
		addrs = append(addrs, d.Address)
		byAddr[d.Address] = d
	}
	assert.Equal(t, []string{"0000:3b:00.0", "0000:41:00.0", "0000:5e:00.0"}, addrs)

	gpu := byAddr["0000:41:00.0"]
	assert.Equal(t, "nvidia", gpu.Driver)
	assert.Equal(t, "1", gpu.NumaNode)
	assert.Equal(t, 16., gpu.Speed)
	assert.Equal(t, 8., gpu.Width)
	assert.Equal(t, 16., gpu.MaxWidth)
	assert.True(t, gpu.Degraded()) // width 8 of 16
	idle := gpu
	idle.Width, idle.Speed = 16, 2.5
	assert.False(t, idle.Degraded()) // GPUs lower the link speed when idle
	nicSlow := PcieDevice{Class: "0x020000", Speed: 8, MaxSpeed: 16, Width: 16, MaxWidth: 16}
	assert.True(t, nicSlow.Degraded())
	assert.Equal(t, map[string]map[string]float64{
		"correctable": {"rxerr": 2, "badtlp": 0, "total_err_cor": 2},
		"fatal":       {"undefined": 0, "total_err_fatal": 0},
	}, gpu.AerErrors)

	nic := byAddr["0000:3b:00.0"]
	assert.False(t, nic.Degraded())
	assert.Equal(t, "mlx5_core", nic.Driver)
	assert.Empty(t, nic.AerErrors)

	nvme := byAddr["0000:5e:00.0"]
	assert.Equal(t, 0., nvme.Speed)
	assert.False(t, nvme.Degraded())
}

func TestCollectHardware(t *testing.T) {
	c := &Collector{RdmaHwCounters: true, PcieAer: true, SysfsRoot: fakeSys(t)}

	collect := func(f func(chan<- prometheus.Metric)) int {
		ch := make(chan prometheus.Metric, 200)
		f(ch)
		close(ch)
		n := 0
		for range ch {
			n++
		}
		return n
	}
	// device info 1 and 2 hw counters
	assert.Equal(t, 3, collect(c.collectRdma))
	// only the gpu reports AER counters: 3 correctable and 2 fatal entries
	assert.Equal(t, 5, collect(c.collectPcie))
}
