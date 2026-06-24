package containers

import (
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
)

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
	L7InboundRequests = map[l7.Protocol]prometheus.CounterOpts{
		l7.ProtocolHTTP:         {Name: "container_http_inbound_requests_total", Help: "Total number of inbound HTTP requests"},
		l7.ProtocolPostgres:     {Name: "container_postgres_inbound_queries_total", Help: "Total number of inbound Postgres queries"},
		l7.ProtocolRedis:        {Name: "container_redis_inbound_queries_total", Help: "Total number of inbound Redis queries"},
		l7.ProtocolMemcached:    {Name: "container_memcached_inbound_queries_total", Help: "Total number of inbound Memcached queries"},
		l7.ProtocolMysql:        {Name: "container_mysql_inbound_queries_total", Help: "Total number of inbound Mysql queries"},
		l7.ProtocolMongo:        {Name: "container_mongo_inbound_queries_total", Help: "Total number of inbound Mongo queries"},
		l7.ProtocolKafka:        {Name: "container_kafka_inbound_requests_total", Help: "Total number of inbound Kafka requests"},
		l7.ProtocolCassandra:    {Name: "container_cassandra_inbound_queries_total", Help: "Total number of inbound Cassandra requests"},
		l7.ProtocolDubbo2:       {Name: "container_dubbo_inbound_requests_total", Help: "Total number of inbound DUBBO requests"},
		l7.ProtocolDNS:          {Name: "container_dns_inbound_requests_total", Help: "Total number of inbound DNS requests"},
		l7.ProtocolClickhouse:   {Name: "container_clickhouse_inbound_queries_total", Help: "Total number of inbound ClickHouse queries"},
		l7.ProtocolZookeeper:    {Name: "container_zookeeper_inbound_requests_total", Help: "Total number of inbound Zookeeper requests"},
		l7.ProtocolFoundationDB: {Name: "container_foundationdb_inbound_requests_total", Help: "Total number of inbound FoundationDB requests"},
	}
	L7InboundLatency = map[l7.Protocol]prometheus.HistogramOpts{
		l7.ProtocolHTTP:         {Name: "container_http_inbound_requests_duration_seconds_total", Help: "Histogram of the response time for each inbound HTTP request"},
		l7.ProtocolPostgres:     {Name: "container_postgres_inbound_queries_duration_seconds_total", Help: "Histogram of the execution time for each inbound Postgres query"},
		l7.ProtocolRedis:        {Name: "container_redis_inbound_queries_duration_seconds_total", Help: "Histogram of the execution time for each inbound Redis query"},
		l7.ProtocolMemcached:    {Name: "container_memcached_inbound_queries_duration_seconds_total", Help: "Histogram of the execution time for each inbound Memcached query"},
		l7.ProtocolMysql:        {Name: "container_mysql_inbound_queries_duration_seconds_total", Help: "Histogram of the execution time for each inbound Mysql query"},
		l7.ProtocolMongo:        {Name: "container_mongo_inbound_queries_duration_seconds_total", Help: "Histogram of the execution time for each inbound Mongo query"},
		l7.ProtocolKafka:        {Name: "container_kafka_inbound_requests_duration_seconds_total", Help: "Histogram of the execution time for each inbound Kafka request"},
		l7.ProtocolCassandra:    {Name: "container_cassandra_inbound_queries_duration_seconds_total", Help: "Histogram of the execution time for each inbound Cassandra request"},
		l7.ProtocolDubbo2:       {Name: "container_dubbo_inbound_requests_duration_seconds_total", Help: "Histogram of the response time for each inbound DUBBO request"},
		l7.ProtocolDNS:          {Name: "container_dns_inbound_requests_duration_seconds_total", Help: "Histogram of the response time for each inbound DNS request"},
		l7.ProtocolClickhouse:   {Name: "container_clickhouse_inbound_queries_duration_seconds_total", Help: "Histogram of the execution time for each inbound ClickHouse query"},
		l7.ProtocolZookeeper:    {Name: "container_zookeeper_inbound_requests_duration_seconds_total", Help: "Histogram of the execution time for each inbound Zookeeper request"},
		l7.ProtocolFoundationDB: {Name: "container_foundationdb_inbound_requests_duration_seconds_total", Help: "Histogram of the execution time for each inbound FoundationDB request"},
	}
)

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
