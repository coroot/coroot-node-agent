package flags

import (
	"net/url"

	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	defaultListenAddress = "127.0.0.1:10300"
	defaultWalDir        = `C:\ProgramData\coroot-node-agent`
	envarPrefix          = "COROOT_"
)

var (
	LogPerSecond = kingpin.Flag("log-per-second", "The number of logs per second").Default("10.0").Envar(envar("LOG_PER_SECOND")).Float64()
	LogBurst     = kingpin.Flag("log-burst", "The maximum number of tokens that can be consumed in a single call to allow").Default("100").Envar(envar("LOG_BURST")).Int()
)

func platformEndpoints(*url.URL) {}
