package flags

import "net/url"

const (
	defaultListenAddress = "127.0.0.1:10300"
	defaultWalDir        = `C:\ProgramData\coroot-node-agent`
	envarPrefix          = "COROOT_"
)

func platformEndpoints(*url.URL) {}
