//go:build !linux && !windows

package flags

import "net/url"

const (
	defaultListenAddress = "127.0.0.1:10300"
	defaultWalDir        = "/tmp/coroot-node-agent"
	envarPrefix          = ""
)

func platformEndpoints(*url.URL) {}
