package main

import (
	"bytes"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/containers"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/node"
	"github.com/coroot/coroot-node-agent/profiling"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/mod/semver"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

var (
	version = "unknown"
)

const minSupportedKernelVersion = "4.16"

func uname() (string, string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	f, err := os.Open("/proc/1/ns/uts")
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	self, err := os.Open("/proc/self/ns/uts")
	if err != nil {
		return "", "", err
	}
	defer self.Close()

	defer func() {
		unix.Setns(int(self.Fd()), unix.CLONE_NEWUTS)
	}()

	err = unix.Setns(int(f.Fd()), unix.CLONE_NEWUTS)
	if err != nil {
		return "", "", err
	}
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return "", "", err
	}
	hostname := string(bytes.Split(utsname.Nodename[:], []byte{0})[0])
	kernelVersion := string(bytes.Split(utsname.Release[:], []byte{0})[0])
	return hostname, kernelVersion, nil
}

func machineID() string {
	for _, p := range []string{"sys/devices/virtual/dmi/id/product_uuid", "etc/machine-id", "var/lib/dbus/machine-id"} {
		payload, err := os.ReadFile(path.Join("/proc/1/root", p))
		if err != nil {
			klog.Warningln("failed to read machine-id:", err)
			continue
		}
		id := strings.TrimSpace(strings.Replace(string(payload), "-", "", -1))
		klog.Infoln("machine-id: ", id)
		return id
	}
	return ""
}

func whitelistNodeExternalNetworks() {
	netdevs, err := node.NetDevices()
	if err != nil {
		klog.Warningln("failed to get network interfaces:", err)
		return
	}
	for _, iface := range netdevs {
		for _, p := range iface.IPPrefixes {
			if p.IP().IsLoopback() || common.IsIpPrivate(p.IP()) {
				continue
			}
			// if the node has an external network IP, whitelist that network
			common.ConnectionFilter.WhitelistPrefix(p)
		}
	}
}

func main() {
	klog.LogToStderr(false)
	klog.SetOutput(&RateLimitedLogOutput{limiter: rate.NewLimiter(10, 100)})

	klog.Infoln("agent version:", version)

	hostname, kv, err := uname()
	if err != nil {
		klog.Exitln("failed to get uname:", err)
	}
	klog.Infoln("hostname:", hostname)
	klog.Infoln("kernel version:", kv)

	ver := common.KernelMajorMinor(kv)
	if ver == "" {
		klog.Exitln("invalid kernel version:", kv)
	}
	if semver.Compare("v"+ver, "v"+minSupportedKernelVersion) == -1 {
		klog.Exitf("the minimum Linux kernel version required is %s or later", minSupportedKernelVersion)
	}

	whitelistNodeExternalNetworks()

	machineId := machineID()
	tracing.Init(machineId, hostname, version)
	logs.Init(machineId, hostname, version)

	registry := prometheus.NewRegistry()
	registerer := prometheus.WrapRegistererWith(prometheus.Labels{"machine_id": machineId}, registry)

	registerer.MustRegister(info("node_agent_info", version))

	if err := registerer.Register(node.NewCollector(hostname, kv)); err != nil {
		klog.Exitln(err)
	}

	processInfoCh := profiling.Init()

	cr, err := containers.NewRegistry(registerer, kv, processInfoCh)
	if err != nil {
		klog.Exitln(err)
	}
	defer cr.Close()

	profiling.Start()
	defer profiling.Stop()

	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{ErrorLog: logger{}, Registry: registerer}))
	klog.Infoln("listening on:", *flags.ListenAddress)
	klog.Errorln(http.ListenAndServe(*flags.ListenAddress, nil))
}

func info(name, version string) prometheus.Collector {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        name,
		ConstLabels: prometheus.Labels{"version": version},
	})
	g.Set(1)
	return g
}

type logger struct{}

func (l logger) Println(v ...interface{}) {
	klog.Errorln(v...)
}

type RateLimitedLogOutput struct {
	limiter *rate.Limiter
}

func (o *RateLimitedLogOutput) Write(data []byte) (int, error) {
	if !o.limiter.Allow() {
		return len(data), nil
	}
	return os.Stderr.Write(data)
}
