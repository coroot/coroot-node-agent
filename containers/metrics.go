package containers

import (
	"github.com/coroot/coroot-node-agent/ebpftracer"
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

	JvmInfo              *prometheus.Desc
	JvmHeapSize          *prometheus.Desc
	JvmHeapUsed          *prometheus.Desc
	JvmGCTime            *prometheus.Desc
	JvmSafepointTime     *prometheus.Desc
	JvmSafepointSyncTime *prometheus.Desc
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

	JvmInfo:              metric("container_jvm_info", "Meta information about the JVM", "jvm", "java_version"),
	JvmHeapSize:          metric("container_jvm_heap_size_bytes", "Total heap size in bytes", "jvm"),
	JvmHeapUsed:          metric("container_jvm_heap_used_bytes", "Used heap size in bytes", "jvm"),
	JvmGCTime:            metric("container_jvm_gc_time_seconds", "Time spent in the given JVM garbage collector in seconds", "jvm", "gc"),
	JvmSafepointTime:     metric("container_jvm_safepoint_time_seconds", "Time the application has been stopped for safepoint operations in seconds", "jvm"),
	JvmSafepointSyncTime: metric("container_jvm_safepoint_sync_time_seconds", "Time spent getting to safepoints in seconds", "jvm"),
}

var (
	L7Requests = map[ebpftracer.L7Protocol]prometheus.CounterOpts{
		ebpftracer.L7ProtocolHTTP:      {Name: "container_http_requests_total", Help: "Total number of outbound HTTP requests"},
		ebpftracer.L7ProtocolPostgres:  {Name: "container_postgres_queries_total", Help: "Total number of outbound Postgres queries"},
		ebpftracer.L7ProtocolRedis:     {Name: "container_redis_queries_total", Help: "Total number of outbound Redis queries"},
		ebpftracer.L7ProtocolMemcached: {Name: "container_memcached_queries_total", Help: "Total number of outbound Memcached queries"},
		ebpftracer.L7ProtocolMysql:     {Name: "container_mysql_queries_total", Help: "Total number of outbound Mysql queries"},
		ebpftracer.L7ProtocolMongo:     {Name: "container_mongo_queries_total", Help: "Total number of outbound Mongo queries"},
		ebpftracer.L7ProtocolKafka:     {Name: "container_kafka_requests_total", Help: "Total number of outbound Kafka requests"},
		ebpftracer.L7ProtocolCassandra: {Name: "container_cassandra_queries_total", Help: "Total number of outbound Cassandra requests"},
	}
	L7Latency = map[ebpftracer.L7Protocol]prometheus.HistogramOpts{
		ebpftracer.L7ProtocolHTTP:      {Name: "container_http_requests_duration_seconds_total", Help: "Histogram of the response time for each outbound HTTP request"},
		ebpftracer.L7ProtocolPostgres:  {Name: "container_postgres_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Postgres query"},
		ebpftracer.L7ProtocolRedis:     {Name: "container_redis_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Redis query"},
		ebpftracer.L7ProtocolMemcached: {Name: "container_memcached_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Memcached query"},
		ebpftracer.L7ProtocolMysql:     {Name: "container_mysql_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Mysql query"},
		ebpftracer.L7ProtocolMongo:     {Name: "container_mongo_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Mongo query"},
		ebpftracer.L7ProtocolKafka:     {Name: "container_kafka_requests_duration_seconds_total", Help: "Histogram of the execution time for each outbound Kafka request"},
		ebpftracer.L7ProtocolCassandra: {Name: "container_cassandra_queries_duration_seconds_total", Help: "Histogram of the execution time for each outbound Cassandra request"},
	}
)

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
