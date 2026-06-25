//go:build windows

package main

import (
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

func registerPlatformCollectors(registerer prometheus.Registerer) func() {
	if *flags.DisableWindowsEventLogMonitoring {
		klog.Infoln("Windows Event Log monitoring disabled")
		return func() {}
	}
	collector, err := logs.NewEventLogCollector(*flags.WindowsEventLogChannels)
	if err != nil {
		klog.Warningf("failed to initialize Windows Event Log collector: %s", err)
		return func() {}
	}
	if err := registerer.Register(collector); err != nil {
		collector.Close()
		klog.Warningf("failed to register Windows Event Log collector: %s", err)
		return func() {}
	}
	return collector.Close
}
