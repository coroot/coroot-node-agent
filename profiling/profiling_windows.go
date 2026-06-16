//go:build windows

package profiling

import "github.com/coroot/coroot-node-agent/containers"

func Init(hostId, hostName string) (chan<- containers.ProcessInfo, chan *containers.ProfilingUpdate) {
	return nil, make(chan *containers.ProfilingUpdate)
}

func Start() {}

func Stop() {}
