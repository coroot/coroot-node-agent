package containers

import (
	"bytes"
	"regexp"
)

var (
	phpCmd    = regexp.MustCompile(`.*php\d*\.?\d*$`)
	pythonCmd = regexp.MustCompile(`.*python\d*\.?\d*$`)
	rubyCmd   = regexp.MustCompile(`.*ruby\d*\.?\d*$`)
	nodejsCmd = regexp.MustCompile(`.*node(js)?\d*\.?\d*$`)
)

func guessApplicationTypeByCmdline(cmdline []byte) string {
	parts := bytes.Split(cmdline, []byte{0})
	if len(parts) == 0 || len(parts[0]) == 0 {
		return ""
	}
	cmd := bytes.TrimSuffix(bytes.Fields(parts[0])[0], []byte{':'})
	switch {
	case bytes.HasSuffix(cmd, []byte("coroot")):
		return "coroot-community-edition"
	case bytes.HasSuffix(cmd, []byte("coroot-ee")):
		return "coroot-enterprise-edition"
	case bytes.HasSuffix(cmd, []byte("coroot-node-agent")):
		return "coroot-node-agent"
	case bytes.HasSuffix(cmd, []byte("coroot-cluster-agent")):
		return "coroot-cluster-agent"
	case bytes.HasSuffix(cmd, []byte("coroot-operator")):
		return "coroot-operator"
	case bytes.HasSuffix(cmd, []byte("memcached")):
		return "memcached"
	case bytes.HasSuffix(cmd, []byte("envoy")):
		return "envoy"
	case bytes.Contains(cmdline, []byte("org.elasticsearch.bootstrap")):
		return "elasticsearch"
	case bytes.Contains(cmdline, []byte("org.opensearch.bootstrap")):
		return "opensearch"
	case bytes.Contains(cmdline, []byte("kafka.Kafka")) || bytes.Contains(cmdline, []byte("io.confluent.support.metrics.SupportedKafka")):
		return "kafka"
	case bytes.HasSuffix(cmd, []byte("mongod")):
		return "mongodb"
	case bytes.HasSuffix(cmd, []byte("mongos")):
		return "mongos"
	case bytes.HasSuffix(cmd, []byte("mysqld")):
		return "mysql"
	case bytes.HasSuffix(cmd, []byte("mariadbd")):
		return "mysql"
	case bytes.Contains(cmdline, []byte("org.apache.zookeeper.server.quorum.QuorumPeerMain")):
		return "zookeeper"
	case bytes.HasSuffix(cmd, []byte("redis-server")):
		return "redis"
	case bytes.HasSuffix(cmd, []byte("redis-sentinel")):
		return "redis-sentinel"
	case bytes.HasSuffix(cmd, []byte("keydb-server")):
		return "keydb"
	case bytes.HasSuffix(cmd, []byte("valkey-server")):
		return "valkey"
	case bytes.HasSuffix(cmd, []byte("dragonfly")):
		return "dragonfly"
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
	case bytes.HasSuffix(cmd, []byte("k3s")):
		return "k3s"
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
	case bytes.HasSuffix(cmd, []byte("ceph-mon")) ||
		bytes.HasSuffix(cmd, []byte("ceph-mgr")) ||
		bytes.HasSuffix(cmd, []byte("ceph-osd")) ||
		bytes.HasSuffix(cmd, []byte("cephcsi")):
		return "ceph"
	case bytes.HasSuffix(cmd, []byte("rook")):
		return "rook"
	case bytes.HasSuffix(cmd, []byte("nats-server")):
		return "nats"
	case bytes.HasSuffix(cmd, []byte("java")):
		return "java"
	case bytes.Contains(cmd, []byte("victoria-metrics")) ||
		bytes.Contains(cmd, []byte("vmstorage")) ||
		bytes.Contains(cmd, []byte("vminsert")) ||
		bytes.Contains(cmd, []byte("vmselect")):
		return "victoria-metrics"
	case bytes.Contains(cmd, []byte("victoria-logs")):
		return "victoria-logs"
	case phpCmd.Match(cmd):
		return "php"
	case pythonCmd.Match(cmd):
		return "python"
	case nodejsCmd.Match(cmd):
		return "nodejs"
	case rubyCmd.Match(cmd):
		return "ruby"
	}
	return ""
}

func guessApplicationTypeByExe(exe string) string {
	switch {
	case phpCmd.MatchString(exe):
		return "php"
	case pythonCmd.MatchString(exe):
		return "python"
	case nodejsCmd.MatchString(exe):
		return "nodejs"
	case rubyCmd.MatchString(exe):
		return "ruby"
	}
	return ""
}
