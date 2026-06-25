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

	TracesEndpoint = kingpin.Flag("traces-endpoint", "The URL of the endpoint to send traces to").Envar(envar("TRACES_ENDPOINT")).URL()
	TracesSampling = kingpin.Flag("traces-sampling", "Trace sampling rate (0.0 to 1.0)").Default("1.0").Envar(envar("TRACES_SAMPLING")).Float64()

	ProfilesEndpoint       = kingpin.Flag("profiles-endpoint", "The URL of the endpoint to send profiles to").Envar(envar("PROFILES_ENDPOINT")).URL()
	WindowsProfile         = kingpin.Flag("windows-profile", "Windows profiling mode: disabled, agent-cpu").Default("disabled").Envar(envar("WINDOWS_PROFILE")).Enum("disabled", "agent-cpu")
	WindowsProfileInterval = kingpin.Flag("windows-profile-interval", "How often to collect Windows agent self profiles").Default("1m").Envar(envar("WINDOWS_PROFILE_INTERVAL")).Duration()
	WindowsProfileDuration = kingpin.Flag("windows-profile-duration", "How long each Windows agent self CPU profile samples").Default("10s").Envar(envar("WINDOWS_PROFILE_DURATION")).Duration()
)

func platformEndpoints(u *url.URL) {
	if *TracesEndpoint == nil {
		*TracesEndpoint = u.JoinPath("/v1/traces")
	}
	if *ProfilesEndpoint == nil {
		*ProfilesEndpoint = u.JoinPath("/v1/profiles")
	}
}
