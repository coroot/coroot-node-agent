package containers

import (
	"bytes"
)

func guessApplicationType(cmdline []byte) string {
	parts := bytes.Split([]byte(cmdline), []byte{0})
	cmd := bytes.TrimSuffix(bytes.Fields(parts[0])[0], []byte{':'})
	switch {
	case bytes.HasSuffix(cmd, []byte("memcached")):
		return "memcached"
	case bytes.HasSuffix(cmd, []byte("envoy")):
		return "envoy"
	case bytes.Contains(cmdline, []byte("org.elasticsearch.bootstrap")):
		return "elasticsearch"
	case bytes.Contains(cmdline, []byte("kafka.Kafka")) || bytes.Contains(cmdline, []byte("io.confluent.support.metrics.SupportedKafka")):
		return "kafka"
	case bytes.HasSuffix(cmd, []byte("mongod")):
		return "mongodb"
	case bytes.HasSuffix(cmd, []byte("mysqld")):
		return "mysql"
	case bytes.Contains(cmdline, []byte("org.apache.zookeeper.server.quorum.QuorumPeerMain")):
		return "zookeeper"
	case bytes.HasSuffix(cmd, []byte("redis-server")):
		return "redis"
	case bytes.HasSuffix(cmd, []byte("redis-sentinel")):
		return "redis-sentinel"
	case bytes.HasSuffix(cmd, []byte("beam.smp")) && bytes.Contains(cmdline, []byte("rabbit")):
		return "rabbitmq"
	case bytes.HasSuffix(cmd, []byte("beam.smp")) && bytes.Contains(cmdline, []byte("couch")):
		return "couchbase"
	case bytes.HasSuffix(cmd, []byte("pgbouncer")):
		return "pgbouncer"
	case bytes.HasSuffix(cmd, []byte("postgres")):
		return "postgres"
	case bytes.HasSuffix(cmd, []byte("haproxy")):
		return "haproxy"
	case bytes.HasSuffix(cmd, []byte("nginx")):
		return "nginx"
	case bytes.HasSuffix(cmd, []byte("kubelet")):
		return "kubelet"
	case bytes.HasSuffix(cmd, []byte("kube-apiserver")):
		return "kube-apiserver"
	case bytes.HasSuffix(cmd, []byte("kube-controller-manager")):
		return "kube-controller-manager"
	case bytes.HasSuffix(cmd, []byte("kube-scheduler")):
		return "kube-scheduler"
	case bytes.HasSuffix(cmd, []byte("etcd")):
		return "etcd"
	case bytes.HasSuffix(cmd, []byte("dockerd")):
		return "dockerd"
	case bytes.HasSuffix(cmd, []byte("consul")):
		return "consul"
	case bytes.Contains(cmdline, []byte("org.apache.cassandra.service.CassandraDaemon")):
		return "cassandra"
	case bytes.HasSuffix(cmd, []byte("clickhouse-server")):
		return "clickhouse"
	case bytes.HasSuffix(cmd, []byte("traefik")):
		return "traefik"
	case bytes.HasSuffix(cmd, []byte("asd")):
		return "aerospike"
	case bytes.HasSuffix(cmd, []byte("httpd")):
		return "httpd"
	case bytes.HasSuffix(cmd, []byte("influxd")):
		return "influxdb"
	case bytes.Contains(cmdline, []byte("org.apache.catalina.startup.Bootstrap")):
		return "tomcat"
	case bytes.HasSuffix(cmd, []byte("vault")):
		return "vault"
	case bytes.HasSuffix(cmd, []byte("proxysql")):
		return "proxysql"
	case bytes.HasSuffix(cmd, []byte("cockroach")):
		return "cockroach"
	case bytes.HasSuffix(cmd, []byte("prometheus")):
		return "prometheus"
	}
	//todo: ceph services, php-fpm, python, nodejs, java
	return ""
}
