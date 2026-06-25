//go:build linux

package main

import "github.com/prometheus/client_golang/prometheus"

func registerPlatformCollectors(prometheus.Registerer) func() {
	return func() {}
}
