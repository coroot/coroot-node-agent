//go:build windows

package main

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"time"

	"github.com/coroot/coroot-node-agent/api"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/host"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/node"
	"github.com/coroot/coroot-node-agent/node/metadata"
	"github.com/coroot/coroot-node-agent/prom"
	"github.com/coroot/coroot-node-agent/windows/containers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/windows/svc"
	"k8s.io/klog/v2"
)

var version = flags.Version

func main() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		klog.Exitln("failed to detect service mode:", err)
	}

	if isService {
		if err := svc.Run("coroot-windows-agent", &windowsService{}); err != nil {
			klog.Exitln("service failed:", err)
		}
		return
	}

	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		close(stop)
	}()
	runAgent(stop)
}

func setupLogging() {
	elog, err := newEventLogWriter("coroot-windows-agent")
	if err != nil {

		return
	}
	klog.LogToStderr(false)
	klog.SetOutput(elog)
}

func runAgent(stop <-chan struct{}) {
	setupLogging()
	klog.Infoln("agent version:", version)

	hostname := node.GetHostname()
	osVersion := node.GetOSVersion()
	klog.Infoln("hostname:", hostname)
	klog.Infoln("os version:", osVersion)

	machineId := host.MachineID()
	systemUuid := host.SystemUUID()

	logs.Init(logs.Config{
		Endpoint:    *flags.LogsEndpoint,
		AuthHeaders: api.AuthHeaders(*flags.ApiKey),
		TLSConfig:   api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify),
	}, machineId, hostname, version)

	nodeCollector := node.NewCollector(hostname, osVersion, metadata.Overrides{
		Provider:          flags.GetString(flags.Provider),
		Region:            flags.GetString(flags.Region),
		AvailabilityZone:  flags.GetString(flags.AvailabilityZone),
		InstanceType:      flags.GetString(flags.InstanceType),
		InstanceLifeCycle: flags.GetString(flags.InstanceLifeCycle),
	})

	registry := prometheus.NewRegistry()

	registerer := prometheus.WrapRegistererWith(
		prometheus.Labels{"machine_id": machineId, "system_uuid": systemUuid},
		registry,
	)
	if err := registerer.Register(nodeCollector); err != nil {
		klog.Exitln(err)
	}

	gpuCollector, err := gpu.NewCollector(gpu.Options{
		Disabled: *flags.DisableGPUMonitoring,
		LibPaths: gpu.DefaultLibPaths(),
	})
	if err != nil {
		klog.Warningln("failed to initialize GPU collector:", err)
	}
	if err := registerer.Register(gpuCollector); err != nil {
		klog.Exitln(err)
	}
	registerer.MustRegister(agentInfo("node_agent_info", version))

	if md := nodeCollector.Metadata(); md != nil {
		region := md.Region
		az := md.AvailabilityZone
		if region != "" && az != "" {
			registerer = prometheus.WrapRegistererWith(prometheus.Labels{"az": az, "region": region}, registerer)
		}
	}

	svcRegistry := containers.NewRegistry(*flags.ScrapeInterval)
	svcRegistry.Start(registerer)

	promCfg := prom.Config{
		Endpoint:       *flags.MetricsEndpoint,
		AuthHeaders:    api.AuthHeaders(*flags.ApiKey),
		TLSConfig:      api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify),
		ScrapeInterval: *flags.ScrapeInterval,
		WalDir:         *flags.WalDir,
		MaxSpoolSize:   int64(*flags.MaxSpoolSize),
	}
	if err := prom.StartAgent(registry, promCfg, machineId, systemUuid); err != nil {
		klog.Exitln(err)
	}

	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registerer}))
	klog.Infoln("listening on:", *flags.ListenAddress)

	srv := &http.Server{Addr: *flags.ListenAddress}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.Exitln(err)
		}
	}()

	<-stop
	klog.Infoln("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		klog.Warningf("HTTP server shutdown error: %s", err)
	}

	svcRegistry.Stop()
	gpuCollector.Close()
	logs.Shutdown(shutdownCtx)
	klog.Infoln("shutdown complete")
}

type windowsService struct{}

func (ws *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runAgent(stop)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			close(stop)
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				klog.Warningln("agent shutdown timed out")
			}
			return false, 0
		}
	}
	return false, 0
}

func agentInfo(name, ver string) prometheus.Collector {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        name,
		ConstLabels: prometheus.Labels{"version": ver},
	})
	g.Set(1)
	return g
}
