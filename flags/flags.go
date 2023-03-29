package flags

import (
	"gopkg.in/alecthomas/kingpin.v2"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
	"os"
	"strings"
)

var (
	ListenAddress     = kingpin.Flag("listen", "Listen address - ip:port or :port").Default("0.0.0.0:80").String()
	CgroupRoot        = kingpin.Flag("cgroupfs-root", "The mount point of the host cgroupfs root").Default("/sys/fs/cgroup").String()
	DisableLogParsing = kingpin.Flag("disable-log-parsing", "Disable container log parsing").Default("false").Bool()
	DisablePinger     = kingpin.Flag("disable-pinger", "Don't ping upstreams").Default("false").Bool()
	DisableL7Tracing  = kingpin.Flag("disable-l7-tracing", "Disable L7 tracing").Default("false").Bool()

	externalNetworksWhitelist = kingpin.Flag("track-public-network", "Allow track connections to the specified IP networks, all private networks are allowed by default (e.g., Y.Y.Y.Y/mask)").Strings()
	ExternalNetworksWhitelist []netaddr.IPPrefix

	Provider          = kingpin.Flag("provider", "`provider` label for `node_cloud_info` metric").Envar("PROVIDER").String()
	Region            = kingpin.Flag("region", "`region` label for `node_cloud_info` metric").Envar("REGION").String()
	AvailabilityZone  = kingpin.Flag("availability-zone", "`availability_zone` label for `node_cloud_info` metric").Envar("AVAILABILITY_ZONE").String()
	InstanceType      = kingpin.Flag("instance-type", "`instance_type` label for `node_cloud_info` metric").Envar("INSTANCE_TYPE").String()
	InstanceLifeCycle = kingpin.Flag("instance-life-cycle", "`instance_life_cycle` label for `node_cloud_info` metric").Envar("INSTANCE_LIFE_CYCLE").String()
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
	if externalNetworksWhitelist != nil {
		for _, prefix := range *externalNetworksWhitelist {
			p, err := netaddr.ParseIPPrefix(prefix)
			if err != nil {
				klog.Fatalf("invalid network %s: %s", prefix, err)
			}
			ExternalNetworksWhitelist = append(ExternalNetworksWhitelist, p)
		}
	}
}
