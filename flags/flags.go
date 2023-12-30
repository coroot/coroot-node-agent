package flags

import (
	"os"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	ListenAddress     = kingpin.Flag("listen", "Listen address - ip:port or :port").Default("0.0.0.0:80").Envar("LISTEN").String()
	CgroupRoot        = kingpin.Flag("cgroupfs-root", "The mount point of the host cgroupfs root").Default("/sys/fs/cgroup").Envar("CGROUPFS_ROOT").String()
	DisableLogParsing = kingpin.Flag("disable-log-parsing", "Disable container log parsing").Default("false").Envar("DISABLE_LOG_PARSING").Bool()
	DisablePinger     = kingpin.Flag("disable-pinger", "Don't ping upstreams").Default("false").Envar("DISABLE_PINGER").Bool()
	DisableL7Tracing  = kingpin.Flag("disable-l7-tracing", "Disable L7 tracing").Default("false").Envar("DISABLE_L7_TRACING").Bool()

	ExternalNetworksWhitelist = kingpin.Flag("track-public-network", "Allow track connections to the specified IP networks, all private networks are allowed by default (e.g., Y.Y.Y.Y/mask)").Envar("TRACK_PUBLIC_NETWORK").Strings()
	EphemeralPortRange        = kingpin.Flag("ephemeral-port-range", "Destination and Listen TCP ports from this range will be skipped").Default("32768-60999").Envar("EPHEMERAL_PORT_RANGE").String()

	Provider          = kingpin.Flag("provider", "`provider` label for `node_cloud_info` metric").Envar("PROVIDER").String()
	Region            = kingpin.Flag("region", "`region` label for `node_cloud_info` metric").Envar("REGION").String()
	AvailabilityZone  = kingpin.Flag("availability-zone", "`availability_zone` label for `node_cloud_info` metric").Envar("AVAILABILITY_ZONE").String()
	InstanceType      = kingpin.Flag("instance-type", "`instance_type` label for `node_cloud_info` metric").Envar("INSTANCE_TYPE").String()
	InstanceLifeCycle = kingpin.Flag("instance-life-cycle", "`instance_life_cycle` label for `node_cloud_info` metric").Envar("INSTANCE_LIFE_CYCLE").String()
	LogPerSecond      = kingpin.Flag("log-per-second", "The number of logs per second").Default("10.0").Envar("LOG_PER_SECOND").Float64()
	LogBurst          = kingpin.Flag("log-burst", "The maximum number of tokens that can be consumed in a single call to allow").Default("100").Envar("LOG_BURST").Int()
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
}
