package main

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/coroot/coroot-node-agent/api"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/containers"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/host"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/node"
	"github.com/coroot/coroot-node-agent/node/metadata"
	"github.com/coroot/coroot-node-agent/profiling"
	"github.com/coroot/coroot-node-agent/prom"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

var (
	version = flags.Version
)

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
	klog.SetOutput(&RateLimitedLogOutput{limiter: rate.NewLimiter(rate.Limit(*flags.LogPerSecond), *flags.LogBurst)})

	if err := runPlatform(); err != nil {
		klog.Exitln(err)
	}
}

func runAgent(ctx context.Context) error {
	klog.Infoln("agent version:", version)

	hostname, kv, err := uname()
	if err != nil {
		return fmt.Errorf("failed to get uname: %w", err)
	}
	klog.Infoln("hostname:", hostname)
	klog.Infoln("kernel version:", kv)

	if err = common.SetKernelVersion(kv); err != nil {
		return err
	}

	checkKernelVersion()

	whitelistNodeExternalNetworks()

	machineID := host.MachineID()
	systemUUID := host.SystemUUID()

	tracing.Init(machineID, hostname, version)
	logs.Init(logs.Config{
		Endpoint:    *flags.LogsEndpoint,
		AuthHeaders: api.AuthHeaders(*flags.ApiKey),
		TLSConfig:   api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify),
	}, machineID, hostname, version)

	nodeCollector := node.NewCollector(hostname, kv, metadata.Overrides{
		Provider:          flags.GetString(flags.Provider),
		Region:            flags.GetString(flags.Region),
		AvailabilityZone:  flags.GetString(flags.AvailabilityZone),
		InstanceType:      flags.GetString(flags.InstanceType),
		InstanceLifeCycle: flags.GetString(flags.InstanceLifeCycle),
	})

	registry := prometheus.NewRegistry()

	registerer := prometheus.WrapRegistererWith(
		prometheus.Labels{"machine_id": machineID, "system_uuid": systemUUID},
		registry,
	)
	if err := registerer.Register(nodeCollector); err != nil {
		return err
	}

	gpuCollector, err := gpu.NewCollector()
	if err != nil {
		klog.Warningln("failed to initialize GPU collector:", err)
	}
	if err := registerer.Register(gpuCollector); err != nil {
		return err
	}
	registerer.MustRegister(info("node_agent_info", version))

	if md := nodeCollector.Metadata(); md != nil {
		region := md.Region
		az := md.AvailabilityZone
		if region != "" && az != "" {
			registerer = prometheus.WrapRegistererWith(prometheus.Labels{"az": az, "region": region}, registerer)
		}
	}
	processInfoCh, profilingCh := profiling.Init(machineID, hostname)
	cr, err := containers.NewRegistry(registerer, processInfoCh, profilingCh, gpuCollector.ProcessUsageSampleCh)
	if err != nil {
		return err
	}
	profiling.Start()

	if err := prom.StartAgent(registry, prom.Config{
		Endpoint:       *flags.MetricsEndpoint,
		AuthHeaders:    api.AuthHeaders(*flags.ApiKey),
		TLSConfig:      api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify),
		ScrapeInterval: *flags.ScrapeInterval,
		WalDir:         *flags.WalDir,
		MaxSpoolSize:   int64(*flags.MaxSpoolSize),
	}, machineID, systemUUID); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{ErrorLog: logger{}, Registry: registerer}))
	klog.Infoln("listening on:", *flags.ListenAddress)

	srv := &http.Server{Addr: *flags.ListenAddress, Handler: mux}
	serverErrCh := make(chan error, 1)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		klog.Infoln("shutdown requested")
	case err := <-serverErrCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		klog.Warningf("HTTP server shutdown error: %s", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		cr.Close()
		profiling.Stop()
		logs.Shutdown(context.Background())
	}()

	select {
	case <-done:
		klog.Infoln("cleanup completed")
	case <-time.After(10 * time.Second):
		klog.Warningln("cleanup timed out, forcing exit")
	}
	return nil
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
