package flags

import (
	"net/url"

	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	defaultListenAddress = "0.0.0.0:80"
	defaultWalDir        = "/tmp/coroot-node-agent"
	envarPrefix          = ""
)

var (
	CgroupRoot              = kingpin.Flag("cgroupfs-root", "The mount point of the host cgroupfs root").Default("/sys/fs/cgroup").Envar("CGROUPFS_ROOT").String()
	DisablePinger           = kingpin.Flag("disable-pinger", "Don't ping upstreams").Default("false").Envar("DISABLE_PINGER").Bool()
	DisableL7Tracing        = kingpin.Flag("disable-l7-tracing", "Disable L7 tracing").Default("false").Envar("DISABLE_L7_TRACING").Bool()
	EnableJavaTls           = kingpin.Flag("enable-java-tls", "Enable Java TLS instrumentation via dynamic agent loading").Default("false").Envar("ENABLE_JAVA_TLS").Bool()
	EnableJavaAsyncProfiler = kingpin.Flag("enable-java-async-profiler", "Enable Java profiling via async-profiler (CPU, memory allocations, lock contention)").Default("false").Envar("ENABLE_JAVA_ASYNC_PROFILER").Bool()
	JavaAsyncProfilerDelay  = kingpin.Flag("java-async-profiler-delay", "Delay in seconds before starting async-profiler after JVM process is detected").Default("30s").Envar("JAVA_ASYNC_PROFILER_DELAY").Duration()
	GoHeapProfilerMode      = kingpin.Flag("go-heap-profiler", "Go heap profiling mode: disabled, enabled (collect from apps with profiling on), force (enable profiling in all Go apps)").Default("enabled").Envar("GO_HEAP_PROFILER").String()
	InstrumentationDelay    = kingpin.Flag("instrumentation-delay", "Delay before enabling Python GIL and Node.js event loop instrumentation, after a process is started").Default("30s").Envar("INSTRUMENTATION_DELAY").Duration()

	SkipSystemdSystemServices = kingpin.Flag("skip-systemd-system-services", "Skip well-known systemd system containers (apt, motd, udev, etc.)").Default("true").Envar("SKIP_SYSTEMD_SYSTEM_SERVICES").Bool()

	LogPerSecond = kingpin.Flag("log-per-second", "The number of logs per second").Default("10.0").Envar("LOG_PER_SECOND").Float64()
	LogBurst     = kingpin.Flag("log-burst", "The maximum number of tokens that can be consumed in a single call to allow").Default("100").Envar("LOG_BURST").Int()

	TracesEndpoint   = kingpin.Flag("traces-endpoint", "The URL of the endpoint to send traces to").Envar("TRACES_ENDPOINT").URL()
	TracesSampling   = kingpin.Flag("traces-sampling", "Trace sampling rate (0.0 to 1.0)").Default("1.0").Envar("TRACES_SAMPLING").Float64()
	ProfilesEndpoint = kingpin.Flag("profiles-endpoint", "The URL of the endpoint to send profiles to").Envar("PROFILES_ENDPOINT").URL()
)

func platformEndpoints(u *url.URL) {
	if *TracesEndpoint == nil {
		*TracesEndpoint = u.JoinPath("/v1/traces")
	}
	if *ProfilesEndpoint == nil {
		*ProfilesEndpoint = u.JoinPath("/v1/profiles")
	}
}
