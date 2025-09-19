package containers

import (
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
)

var metrics = struct {
	ContainerInfo *prometheus.Desc
	Restarts      *prometheus.Desc

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

	NetListenInfo            *prometheus.Desc
	NetConnectionsSuccessful *prometheus.Desc
	NetConnectionsTotalTime  *prometheus.Desc
	NetConnectionsFailed     *prometheus.Desc
	NetConnectionsActive     *prometheus.Desc
	NetRetransmits           *prometheus.Desc
	NetLatency               *prometheus.Desc
	NetBytesSent             *prometheus.Desc
	NetBytesReceived         *prometheus.Desc

	LogMessages *prometheus.Desc

	ApplicationType *prometheus.Desc

	JvmInfo              *prometheus.Desc
	JvmHeapSize          *prometheus.Desc
	JvmHeapUsed          *prometheus.Desc
	JvmGCTime            *prometheus.Desc
	JvmSafepointTime     *prometheus.Desc
	JvmSafepointSyncTime *prometheus.Desc

	PythonThreadLockWaitTime   *prometheus.Desc
	NodejsEventLoopBlockedTime *prometheus.Desc

	GpuUsagePercent       *prometheus.Desc
	GpuMemoryUsagePercent *prometheus.Desc

	Ip2Fqdn *prometheus.Desc
}{
	ContainerInfo: metric("container_info", "Meta information about the container", "image", "systemd_triggered_by"),

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

	NetListenInfo:            metric("container_net_tcp_listen_info", "Listen address of the container", "listen_addr", "proxy"),
	NetConnectionsSuccessful: metric("container_net_tcp_successful_connects_total", "Total number of successful TCP connects", "destination", "actual_destination"),
	NetConnectionsTotalTime:  metric("container_net_tcp_connection_time_seconds_total", "Time spent on TCP connections", "destination", "actual_destination"),
	NetConnectionsFailed:     metric("container_net_tcp_failed_connects_total", "Total number of failed TCP connects", "destination"),
	NetConnectionsActive:     metric("container_net_tcp_active_connections", "Number of active outbound connections used by the container", "destination", "actual_destination"),
	NetRetransmits:           metric("container_net_tcp_retransmits_total", "Total number of retransmitted TCP segments", "destination", "actual_destination"),
	NetLatency:               metric("container_net_latency_seconds", "Round-trip time between the container and a remote IP", "destination_ip"),
	NetBytesSent:             metric("container_net_tcp_bytes_sent_total", "Total number of bytes sent to the peer", "destination", "actual_destination"),
	NetBytesReceived:         metric("container_net_tcp_bytes_received_total", "Total number of bytes received from the peer", "destination", "actual_destination"),

	LogMessages: metric("container_log_messages_total", "Number of messages grouped by the automatically extracted repeated pattern", "source", "level", "pattern_hash", "sample"),

	ApplicationType: metric("container_application_type", "Type of the application running in the container (e.g. memcached, postgres, mysql)", "application_type"),

	JvmInfo:              metric("container_jvm_info", "Meta information about the JVM", "jvm", "java_version"),
	JvmHeapSize:          metric("container_jvm_heap_size_bytes", "Total heap size in bytes", "jvm"),
	JvmHeapUsed:          metric("container_jvm_heap_used_bytes", "Used heap size in bytes", "jvm"),
	JvmGCTime:            metric("container_jvm_gc_time_seconds", "Time spent in the given JVM garbage collector in seconds", "jvm", "gc"),
	JvmSafepointTime:     metric("container_jvm_safepoint_time_seconds", "Time the application has been stopped for safepoint operations in seconds", "jvm"),
	JvmSafepointSyncTime: metric("container_jvm_safepoint_sync_time_seconds", "Time spent getting to safepoints in seconds", "jvm"),

	Ip2Fqdn: metric("ip_to_fqdn", "Mapping IP addresses to FQDNs based on DNS requests initiated by containers", "ip", "fqdn"),

	PythonThreadLockWaitTime:   metric("container_python_thread_lock_wait_time_seconds", "Time spent waiting acquiring GIL in seconds"),
	NodejsEventLoopBlockedTime: metric("container_nodejs_event_loop_blocked_time_seconds_total", "Total time the Node.js event loop spent blocked"),

	GpuUsagePercent:       metric("container_resources_gpu_usage_percent", "Percent of GPU compute resources used by the container", "gpu_uuid"),
	GpuMemoryUsagePercent: metric("container_resources_gpu_memory_usage_percent", "Percent of GPU memory used by the container", "gpu_uuid"),
}

var (
	L7Requests = map[l7.Protocol]prometheus.CounterOpts{
		l7.ProtocolHTTP:         {Name: "container_http_requests_total", Help: "Total number of outbound HTTP requests"},
		l7.ProtocolPostgres:     {Name: "container_postgres_queries_total", Help: "Total number of outbound Postgres queries"},
		l7.ProtocolRedis:        {Name: "container_redis_queries_total", Help: "Total number of outbound Redis queries"},
		l7.ProtocolMemcached:    {Name: "container_memcached_queries_total", Help: "Total number of outbound Memcached queries"},
		l7.ProtocolMysql:        {Name: "container_mysql_queries_total", Help: "Total number of outbound Mysql queries"},
		l7.ProtocolMongo:        {Name: "container_mongo_queries_total", Help: "Total number of outbound Mongo queries"},
		l7.ProtocolKafka:        {Name: "container_kafka_requests_total", Help: "Total number of outbound Kafka requests"},
		l7.ProtocolCassandra:    {Name: "container_cassandra_queries_total", Help: "Total number of outbound Cassandra requests"},
		l7.ProtocolRabbitmq:     {Name: "container_rabbitmq_messages_total", Help: "Total number of Rabbitmq messages produced or consumed by the container"},
		l7.ProtocolNats:         {Name: "container_nats_messages_total", Help: "Total number of NATS messages produced or consumed by the container"},
		l7.ProtocolDubbo2:       {Name: "container_dubbo_requests_total", Help: "Total number of outbound DUBBO requests"},
		l7.ProtocolDNS:          {Name: "container_dns_requests_total", Help: "Total number of outbound DNS requests"},
		l7.ProtocolClickhouse:   {Name: "container_clickhouse_queries_total", Help: "Total number of outbound ClickHouse queries"},
		l7.ProtocolZookeeper:    {Name: "container_zookeeper_requests_total", Help: "Total number of outbound Zookeeper requests"},
		l7.ProtocolFoundationDB: {Name: "container_foundationdb_requests_total", Help: "Total number of outbound FoundationDB requests"},
	}
	L7Latency = map[l7.Protocol]prometheus.HistogramOpts{
		l7.ProtocolHTTP:         {Name: "container_http_requests_duration_seconds_total", Help: "Histogram of the response time for each outbound HTTP request"},
		l7.ProtocolPostgres:     {Name: "container_postgres_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Postgres query"},
		l7.ProtocolRedis:        {Name: "container_redis_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Redis query"},
		l7.ProtocolMemcached:    {Name: "container_memcached_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Memcached query"},
		l7.ProtocolMysql:        {Name: "container_mysql_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Mysql query"},
		l7.ProtocolMongo:        {Name: "container_mongo_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Mongo query"},
		l7.ProtocolKafka:        {Name: "container_kafka_requests_duration_seconds_total", Help: "Histogram of the execution time for each outbound Kafka request"},
		l7.ProtocolCassandra:    {Name: "container_cassandra_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Cassandra request"},
		l7.ProtocolDubbo2:       {Name: "container_dubbo_requests_duration_seconds_total", Help: "Histogram of the response time for each outbound DUBBO request"},
		l7.ProtocolDNS:          {Name: "container_dns_requests_duration_seconds_total", Help: "Histogram of the response time for each outbound DNS request"},
		l7.ProtocolClickhouse:   {Name: "container_clickhouse_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound ClickHouse query"},
		l7.ProtocolZookeeper:    {Name: "container_zookeeper_requests_duration_seconds_total", Help: "Histogram of the execution time for each outbound Zookeeper request"},
		l7.ProtocolFoundationDB: {Name: "container_foundationdb_requests_duration_seconds_total", Help: "Histogram of the execution time for each outbound FoundationDB request"},
	}
)

func metric(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labels, nil)
}

func newCounter(name, help string, constLabels prometheus.Labels) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help, ConstLabels: constLabels})
}

func newCounterVec(name, help string, constLabels prometheus.Labels, labelNames ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help, ConstLabels: constLabels}, labelNames)
}

func newGauge(name, help string, constLabels prometheus.Labels) prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help, ConstLabels: constLabels})
}

func newGaugeVec(name, help string, constLabels prometheus.Labels, labelNames ...string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help, ConstLabels: constLabels}, labelNames)
}
