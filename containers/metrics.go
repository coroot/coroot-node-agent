package containers

import (
	"github.com/prometheus/client_golang/prometheus"
	"reflect"
)

var metrics = struct {
	Restarts *prometheus.Desc

	CPULimit      *prometheus.Desc
	CPUUsage      *prometheus.Desc
	CPUDelay      *prometheus.Desc
	ThrottledTime *prometheus.Desc

	MemoryLimit *prometheus.Desc
	MemoryRss   *prometheus.Desc
	MemoryCache *prometheus.Desc
	OOMKills    *prometheus.Desc

	DiskDelay      *prometheus.Desc
	DiskSize       *prometheus.Desc
	DiskUsed       *prometheus.Desc
	DiskReserved   *prometheus.Desc
	DiskReadOps    *prometheus.Desc
	DiskReadBytes  *prometheus.Desc
	DiskWriteOps   *prometheus.Desc
	DiskWriteBytes *prometheus.Desc

	NetListenInfo         *prometheus.Desc
	NetConnectsSuccessful *prometheus.Desc
	NetConnectsFailed     *prometheus.Desc
	NetConnectionsActive  *prometheus.Desc
	NetRetransmits        *prometheus.Desc
	NetLatency            *prometheus.Desc

	LogMessages *prometheus.Desc

	ApplicationType *prometheus.Desc
}{
	Restarts: metric("container_restarts_total", "Number of times the container was restarted"),

	CPULimit:      metric("container_resources_cpu_limit_cores", "CPU limit of the container"),
	CPUUsage:      metric("container_resources_cpu_usage_seconds_total", "Total CPU time consumed by the container"),
	CPUDelay:      metric("container_resources_cpu_delay_seconds_total", "Total time duration processes of the container have been waiting for a CPU (while being runnable)"),
	ThrottledTime: metric("container_resources_cpu_throttled_seconds_total", "Total time duration the container has been throttled"),

	MemoryLimit: metric("container_resources_memory_limit_bytes", "Memory limit of the container"),
	MemoryRss:   metric("container_resources_memory_rss_bytes", "Amount of physical memory used by the container (doesn't include page cache)"),
	MemoryCache: metric("container_resources_memory_cache_bytes", "Amount of page cache memory allocated by the container"),
	OOMKills:    metric("container_oom_kills_total", "Total number of times the container was terminated by the OOM killer"),

	DiskDelay:      metric("container_resources_disk_delay_seconds_total", "Total time duration processes of the container have been waiting fot I/Os to complete"),
	DiskSize:       metric("container_resources_disk_size_bytes", "Total capacity of the volume", "mount_point", "device", "volume"),
	DiskUsed:       metric("container_resources_disk_used_bytes", "Used capacity of the volume", "mount_point", "device", "volume"),
	DiskReserved:   metric("container_resources_disk_reserved_bytes", "Reserved capacity of the volume", "mount_point", "device", "volume"),
	DiskReadOps:    metric("container_resources_disk_reads_total", "Total number of reads completed successfully by the container", "mount_point", "device", "volume"),
	DiskReadBytes:  metric("container_resources_disk_read_bytes_total", "Total number of bytes read from the disk by the container", "mount_point", "device", "volume"),
	DiskWriteOps:   metric("container_resources_disk_writes_total", "Total number of writes completed successfully by the container", "mount_point", "device", "volume"),
	DiskWriteBytes: metric("container_resources_disk_written_bytes_total", "Total number of bytes written to the disk by the container", "mount_point", "device", "volume"),

	NetListenInfo:         metric("container_net_tcp_listen_info", "Listen address of the container", "listen_addr", "proxy"),
	NetConnectsSuccessful: metric("container_net_tcp_successful_connects_total", "Total number of successful TCP connects", "destination", "actual_destination"),
	NetConnectsFailed:     metric("container_net_tcp_failed_connects_total", "Total number of failed TCP connects", "destination"),
	NetConnectionsActive:  metric("container_net_tcp_active_connections", "Number of active outbound connections used by the container", "destination", "actual_destination"),
	NetRetransmits:        metric("container_net_tcp_retransmits_total", "Total number of retransmitted TCP segments", "destination", "actual_destination"),
	NetLatency:            metric("container_net_latency_seconds", "Round-trip time between the container and a remote IP", "destination_ip"),

	LogMessages: metric("container_log_messages_total", "Number of messages grouped by the automatically extracted repeated pattern", "source", "level", "pattern_hash", "sample"),

	ApplicationType: metric("container_application_type", "Type of the application running in the container (e.g. memcached, postgres, mysql)", "application_type"),
}

func metric(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labels, nil)
}

var metricsList []*prometheus.Desc

func init() {
	v := reflect.ValueOf(metrics)
	for i := 0; i < v.NumField(); i++ {
		metricsList = append(metricsList, v.Field(i).Interface().(*prometheus.Desc))
	}
}
