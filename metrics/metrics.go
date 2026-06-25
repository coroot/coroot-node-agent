package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	ContainerInfo = metric("container_info", "Meta information about the container", "image", "systemd_triggered_by", "systemd_type")

	Restarts = metric("container_restarts_total", "Number of times the container was restarted")

	CPULimit      = metric("container_resources_cpu_limit_cores", "CPU limit of the container")
	CPUUsage      = metric("container_resources_cpu_usage_seconds_total", "Total CPU time consumed by the container")
	CPUDelay      = metric("container_resources_cpu_delay_seconds_total", "Total time duration processes of the container have been waiting for a CPU (while being runnable)")
	ThrottledTime = metric("container_resources_cpu_throttled_seconds_total", "Total time duration the container has been throttled")

	MemoryLimit = metric("container_resources_memory_limit_bytes", "Memory limit of the container")
	MemoryRss   = metric("container_resources_memory_rss_bytes", "Amount of physical memory used by the container (doesn't include page cache)")
	MemoryCache = metric("container_resources_memory_cache_bytes", "Amount of page cache memory allocated by the container")
	OOMKills    = metric("container_oom_kills_total", "Total number of times the container was terminated by the OOM killer")

	PsiCPU    = metric("container_resources_cpu_pressure_waiting_seconds_total", "Total time in seconds tha the container were delayed due to CPU pressure", "kind")
	PsiMemory = metric("container_resources_memory_pressure_waiting_seconds_total", "Total time in seconds that the container were delayed due to memory pressure", "kind")
	PsiIO     = metric("container_resources_io_pressure_waiting_seconds_total", "Total time in seconds that the container were delayed due to I/O pressure", "kind")

	DiskDelay      = metric("container_resources_disk_delay_seconds_total", "Total time duration processes of the container have been waiting fot I/Os to complete")
	DiskSize       = metric("container_resources_disk_size_bytes", "Total capacity of the volume", "mount_point", "device", "volume")
	DiskUsed       = metric("container_resources_disk_used_bytes", "Used capacity of the volume", "mount_point", "device", "volume")
	DiskReserved   = metric("container_resources_disk_reserved_bytes", "Reserved capacity of the volume", "mount_point", "device", "volume")
	DiskReadOps    = metric("container_resources_disk_reads_total", "Total number of reads completed successfully by the container", "mount_point", "device", "volume")
	DiskReadBytes  = metric("container_resources_disk_read_bytes_total", "Total number of bytes read from the disk by the container", "mount_point", "device", "volume")
	DiskWriteOps   = metric("container_resources_disk_writes_total", "Total number of writes completed successfully by the container", "mount_point", "device", "volume")
	DiskWriteBytes = metric("container_resources_disk_written_bytes_total", "Total number of bytes written to the disk by the container", "mount_point", "device", "volume")

	NetListenInfo            = metric("container_net_tcp_listen_info", "Listen address of the container", "listen_addr", "proxy")
	NetConnectionsSuccessful = metric("container_net_tcp_successful_connects_total", "Total number of successful TCP connects", "destination", "actual_destination")
	NetConnectionsTotalTime  = metric("container_net_tcp_connection_time_seconds_total", "Time spent on TCP connections", "destination", "actual_destination")
	NetConnectionsFailed     = metric("container_net_tcp_failed_connects_total", "Total number of failed TCP connects", "destination")
	NetConnectionsActive     = metric("container_net_tcp_active_connections", "Number of active outbound connections used by the container", "destination", "actual_destination")
	NetRetransmits           = metric("container_net_tcp_retransmits_total", "Total number of retransmitted TCP segments", "destination", "actual_destination")
	NetLatency               = metric("container_net_latency_seconds", "Round-trip time between the container and a remote IP", "destination_ip")
	NetBytesSent             = metric("container_net_tcp_bytes_sent_total", "Total number of bytes sent to the peer", "destination", "actual_destination")
	NetBytesReceived         = metric("container_net_tcp_bytes_received_total", "Total number of bytes received from the peer", "destination", "actual_destination")

	LogMessages = metric("container_log_messages_total", "Number of messages grouped by the automatically extracted repeated pattern", "source", "level", "pattern_hash", "sample")

	ApplicationType = metric("container_application_type", "Type of the application running in the container (e.g. memcached, postgres, mysql)", "application_type")

	JvmInfo              = metric("container_jvm_info", "Meta information about the JVM", "jvm", "java_version")
	JvmHeapSize          = metric("container_jvm_heap_size_bytes", "Total heap size in bytes", "jvm")
	JvmHeapUsed          = metric("container_jvm_heap_used_bytes", "Used heap size in bytes", "jvm")
	JvmHeapMaxSize       = metric("container_jvm_heap_max_size_bytes", "Maximum heap size in bytes (-Xmx)", "jvm")
	JvmGCTime            = metric("container_jvm_gc_time_seconds", "Time spent in the given JVM garbage collector in seconds", "jvm", "gc")
	JvmSafepointTime     = metric("container_jvm_safepoint_time_seconds", "Time the application has been stopped for safepoint operations in seconds", "jvm")
	JvmSafepointSyncTime = metric("container_jvm_safepoint_sync_time_seconds", "Time spent getting to safepoints in seconds", "jvm")
	JvmAllocBytes        = metric("container_jvm_alloc_bytes_total", "Total bytes allocated observed by async-profiler", "jvm")
	JvmAllocObjects      = metric("container_jvm_alloc_objects_total", "Total objects allocated observed by async-profiler", "jvm")
	JvmLockContentions   = metric("container_jvm_lock_contentions_total", "Total number of lock contentions observed by async-profiler", "jvm")
	JvmLockTime          = metric("container_jvm_lock_time_seconds_total", "Total time spent waiting for locks observed by async-profiler", "jvm")
	JvmProfilingStatus   = metric("container_jvm_profiling_status", "1 if async-profiler is enabled, 0 if disabled", "jvm")

	GoAllocBytes   = metric("container_go_alloc_bytes_total", "Total bytes allocated by a Go application")
	GoAllocObjects = metric("container_go_alloc_objects_total", "Total objects allocated by a Go application")

	Ip2Fqdn = metric("ip_to_fqdn", "Mapping IP addresses to FQDNs based on DNS requests initiated by containers", "ip", "fqdn")

	PythonThreadLockWaitTime   = metric("container_python_thread_lock_wait_time_seconds", "Time spent waiting acquiring GIL in seconds")
	NodejsEventLoopBlockedTime = metric("container_nodejs_event_loop_blocked_time_seconds_total", "Total time the Node.js event loop spent blocked")

	GpuUsagePercent       = metric("container_resources_gpu_usage_percent", "Percent of GPU compute resources used by the container", "gpu_uuid")
	GpuMemoryUsagePercent = metric("container_resources_gpu_memory_usage_percent", "Percent of GPU memory used by the container", "gpu_uuid")

	NodeGpuInfo            = metric("node_gpu_info", "Meta information about the GPU", "gpu_uuid", "name", "driver_version")
	NodeGpuMemoryTotal     = metric("node_resources_gpu_memory_total_bytes", "Total memory available on the GPU in bytes", "gpu_uuid")
	NodeGpuMemoryUsed      = metric("node_resources_gpu_memory_used_bytes", "GPU memory currently in use in bytes", "gpu_uuid")
	NodeGpuMemoryUsageAvg  = metric("node_resources_gpu_memory_utilization_percent_avg", "Average GPU memory utilization (percentage) over the collection interval", "gpu_uuid")
	NodeGpuMemoryUsagePeak = metric("node_resources_gpu_memory_utilization_percent_peak", "Peak GPU memory utilization (percentage) over the collection interval", "gpu_uuid")
	NodeGpuUsageAvg        = metric("node_resources_gpu_utilization_percent_avg", "Average GPU core utilization (percentage) over the collection interval", "gpu_uuid")
	NodeGpuUsagePeak       = metric("node_resources_gpu_utilization_percent_peak", "Peak GPU core utilization (percentage) over the collection interval", "gpu_uuid")
	NodeGpuTemperature     = metric("node_resources_gpu_temperature_celsius", "Current temperature of the GPU in Celsius", "gpu_uuid")
	NodeGpuPowerWatts      = metric("node_resources_gpu_power_usage_watts", "Current power usage of the GPU in watts", "gpu_uuid")

	NodeInfo            = metric("node_info", "Meta information about the node", "hostname", "kernel_version")
	NodeCloudInfo       = metric("node_cloud_info", "Meta information about the cloud instance", "provider", "account_id", "instance_id", "instance_type", "instance_life_cycle", "region", "availability_zone", "availability_zone_id", "local_ipv4", "public_ipv4")
	NodeUptime          = metric("node_uptime_seconds", "Uptime of the node in seconds")
	NodeCPUUsage        = metric("node_resources_cpu_usage_seconds_total", "The amount of CPU time spent in each mode", "mode")
	NodeCPULogicalCores = metric("node_resources_cpu_logical_cores", "The number of logical CPU cores")
	NodeMemoryTotal     = metric("node_resources_memory_total_bytes", "The total amount of physical memory")
	NodeMemoryFree      = metric("node_resources_memory_free_bytes", "The amount of unassigned memory")
	NodeMemoryAvailable = metric("node_resources_memory_available_bytes", "The total amount of available memory")
	NodeMemoryCached    = metric("node_resources_memory_cached_bytes", "The amount of memory used as page cache")

	NodeDiskReads        = metric("node_resources_disk_reads_total", "The total number of reads completed successfully", "device")
	NodeDiskWrites       = metric("node_resources_disk_writes_total", "The total number of writes completed successfully", "device")
	NodeDiskReadBytes    = metric("node_resources_disk_read_bytes_total", "The total number of bytes read from the disk", "device")
	NodeDiskWrittenBytes = metric("node_resources_disk_written_bytes_total", "The total number of bytes written to the disk", "device")
	NodeDiskReadTime     = metric("node_resources_disk_read_time_seconds_total", "The total number of seconds spent reading", "device")
	NodeDiskWriteTime    = metric("node_resources_disk_write_time_seconds_total", "The total number of seconds spent writing", "device")
	NodeDiskIoTime       = metric("node_resources_disk_io_time_seconds_total", "The total number of seconds the disk spent doing I/O", "device")

	NodeNetRxBytes     = metric("node_net_received_bytes_total", "The total number of bytes received", "interface")
	NodeNetTxBytes     = metric("node_net_transmitted_bytes_total", "The total number of bytes transmitted", "interface")
	NodeNetRxPackets   = metric("node_net_received_packets_total", "The total number of packets received", "interface")
	NodeNetTxPackets   = metric("node_net_transmitted_packets_total", "The total number of packets transmitted", "interface")
	NodeNetInterfaceUp = metric("node_net_interface_up", "Status of the interface (0:down, 1:up)", "interface")
	NodeNetInterfaceIP = metric("node_net_interface_ip", "IP address assigned to the interface", "interface", "ip")
)

func metric(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labels, nil)
}

func Gauge(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labelValues...)
}

func Counter(desc *prometheus.Desc, value float64, labelValues ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, labelValues...)
}
