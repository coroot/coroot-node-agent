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

	DisableWindowsEventLogMonitoring = kingpin.Flag("disable-windows-event-log-monitoring", "Disable Windows Event Log monitoring").Default("false").Envar(envar("DISABLE_WINDOWS_EVENT_LOG_MONITORING")).Bool()
	WindowsEventLogChannels          = kingpin.Flag("windows-event-log-channel", "Windows Event Log channel to subscribe to. Can be specified multiple times.").Default("Application", "System").Envar(envar("WINDOWS_EVENT_LOG_CHANNELS")).Strings()
)

func platformEndpoints(*url.URL) {}
