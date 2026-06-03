package flags

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"
)

func envar(name string) string {
	return envarPrefix + name
}

var (
	ListenAddress = kingpin.Flag("listen", "Listen address - ip:port or :port").Default(defaultListenAddress).Envar(envar("LISTEN")).String()

	DisableLogParsing    = kingpin.Flag("disable-log-parsing", "Disable container log parsing").Default("false").Envar(envar("DISABLE_LOG_PARSING")).Bool()
	DisableGPUMonitoring = kingpin.Flag("disable-gpu-monitoring", "Disable GPU monitoring (NVML)").Default("false").Envar(envar("DISABLE_GPU_MONITORING")).Bool()

	ContainerAllowlist = kingpin.Flag("container-allowlist", "List of allowed containers (regex patterns)").Envar(envar("CONTAINER_ALLOWLIST")).Strings()
	ContainerDenylist  = kingpin.Flag("container-denylist", "List of denied containers (regex patterns)").Envar(envar("CONTAINER_DENYLIST")).Strings()
	MinContainerAge    = kingpin.Flag("min-container-age", "Don't report metrics for containers younger than this. Suppresses short-lived job/cronjob pods that produce high-cardinality series. 0 disables.").Default("30s").Envar(envar("MIN_CONTAINER_AGE")).Duration()

	MaxFQDNsPerContainer = kingpin.Flag("max-fqdns-per-container", "Max unique FQDN values per container, extras are bucketed under '~other'").Default("50").Envar(envar("MAX_FQDNS_PER_CONTAINER")).Int()

	ExcludeHTTPMetricsByPath  = kingpin.Flag("exclude-http-requests-by-path", "Skip HTTP metrics and traces by path").Envar(envar("EXCLUDE_HTTP_REQUESTS_BY_PATH")).Strings()
	ExternalNetworksWhitelist = kingpin.Flag("track-public-network", "Allow track connections to the specified IP networks, all private networks are allowed by default (e.g., Y.Y.Y.Y/mask)").Envar(envar("TRACK_PUBLIC_NETWORK")).Default("0.0.0.0/0").Strings()
	EphemeralPortRange        = kingpin.Flag("ephemeral-port-range", "Destination and Listen TCP ports from this range will be skipped").Default("32768-60999").Envar(envar("EPHEMERAL_PORT_RANGE")).String()

	Provider          = kingpin.Flag("provider", "`provider` label for `node_cloud_info` metric").Envar(envar("PROVIDER")).String()
	Region            = kingpin.Flag("region", "`region` label for `node_cloud_info` metric").Envar(envar("REGION")).String()
	AvailabilityZone  = kingpin.Flag("availability-zone", "`availability_zone` label for `node_cloud_info` metric").Envar(envar("AVAILABILITY_ZONE")).String()
	InstanceType      = kingpin.Flag("instance-type", "`instance_type` label for `node_cloud_info` metric").Envar(envar("INSTANCE_TYPE")).String()
	InstanceLifeCycle = kingpin.Flag("instance-life-cycle", "`instance_life_cycle` label for `node_cloud_info` metric").Envar(envar("INSTANCE_LIFE_CYCLE")).String()

	LogPatternsPerContainer = kingpin.Flag("log-patterns-per-container", "Max unique log patterns per container per level").Default("256").Envar(envar("LOG_PATTERNS_PER_CONTAINER")).Int()
	MaxLabelLength          = kingpin.Flag("max-label-length", "Maximum length of a metric label value").Default("4096").Envar(envar("MAX_LABEL_LENGTH")).Int()

	CollectorEndpoint  = kingpin.Flag("collector-endpoint", "A base endpoint URL for metrics, traces, logs, and profiles").Envar(envar("COLLECTOR_ENDPOINT")).URL()
	ApiKey             = kingpin.Flag("api-key", "Coroot API key").Envar(envar("API_KEY")).String()
	MetricsEndpoint    = kingpin.Flag("metrics-endpoint", "The URL of the endpoint to send metrics to").Envar(envar("METRICS_ENDPOINT")).URL()
	LogsEndpoint       = kingpin.Flag("logs-endpoint", "The URL of the endpoint to send logs to").Envar(envar("LOGS_ENDPOINT")).URL()
	InsecureSkipVerify = kingpin.Flag("insecure-skip-verify", "whether to skip verifying the certificate or not").Envar(envar("INSECURE_SKIP_VERIFY")).Default("false").Bool()
	CAFile             = kingpin.Flag("ca-file", "Path to the custom CA certificate file").Envar(envar("CA_FILE")).String()

	ScrapeInterval = kingpin.Flag("scrape-interval", "How often to gather metrics from the agent").Default("15s").Envar(envar("SCRAPE_INTERVAL")).Duration()
	WalDir         = kingpin.Flag("wal-dir", "Path to where the agent stores data (e.g. the metrics Write-Ahead Log)").Default(defaultWalDir).Envar(envar("WAL_DIR")).String()
	MaxSpoolSize   = kingpin.Flag("max-spool-size", "Maximum size of the on-disk spool used to buffer data when it cannot be sent to collector. Supports size suffixes like KB, MB, or GB.").Default("500MB").Envar(envar("MAX_SPOOL_SIZE")).Bytes()

	agentVersion = kingpin.Flag("version", "Print version and exit").Default("false").Bool()
	Version      = "unknown"
)

func GetString(fl *string) string {
	if fl == nil {
		return ""
	}
	return *fl
}

func init() {
	if strings.HasSuffix(os.Args[0], ".test") {
		return
	}

	kingpin.HelpFlag.Short('h').Hidden()
	kingpin.Parse()

	if *agentVersion {
		fmt.Println("Version:", Version)
		os.Exit(0)
	}

	if *CollectorEndpoint != nil {
		u := *CollectorEndpoint
		if *MetricsEndpoint == nil {
			*MetricsEndpoint = u.JoinPath("/v1/metrics")
		}
		if *LogsEndpoint == nil {
			*LogsEndpoint = u.JoinPath("/v1/logs")
		}
		platformEndpoints(u)
	}

	if *MetricsEndpoint != nil {
		*ListenAddress = "127.0.0.1:10300"
	}
}
