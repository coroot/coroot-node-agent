package l7

import (
	"strconv"
	"time"
)

type Protocol uint8

const (
	ProtocolHTTP         Protocol = 1
	ProtocolPostgres     Protocol = 2
	ProtocolRedis        Protocol = 3
	ProtocolMemcached    Protocol = 4
	ProtocolMysql        Protocol = 5
	ProtocolMongo        Protocol = 6
	ProtocolKafka        Protocol = 7
	ProtocolCassandra    Protocol = 8
	ProtocolRabbitmq     Protocol = 9
	ProtocolNats         Protocol = 10
	ProtocolHTTP2        Protocol = 11
	ProtocolDubbo2       Protocol = 12
	ProtocolDNS          Protocol = 13
	ProtocolClickhouse   Protocol = 14
	ProtocolZookeeper    Protocol = 15
	ProtocolFoundationDB Protocol = 16
)

func (p Protocol) String() string {
	switch p {
	case ProtocolHTTP:
		return "HTTP"
	case ProtocolPostgres:
		return "Postgres"
	case ProtocolRedis:
		return "Redis"
	case ProtocolMemcached:
		return "Memcached"
	case ProtocolMysql:
		return "Mysql"
	case ProtocolMongo:
		return "Mongo"
	case ProtocolKafka:
		return "Kafka"
	case ProtocolCassandra:
		return "Cassandra"
	case ProtocolRabbitmq:
		return "Rabbitmq"
	case ProtocolNats:
		return "NATS"
	case ProtocolHTTP2:
		return "HTTP2"
	case ProtocolDubbo2:
		return "Dubbo2"
	case ProtocolDNS:
		return "DNS"
	case ProtocolClickhouse:
		return "ClickHouse"
	case ProtocolZookeeper:
		return "Zookeeper"
	case ProtocolFoundationDB:
		return "FoundationDB"
	}
	return "UNKNOWN:" + strconv.Itoa(int(p))
}

type Method uint8

const (
	MethodUnknown           Method = 0
	MethodProduce           Method = 1
	MethodConsume           Method = 2
	MethodStatementPrepare  Method = 3
	MethodStatementClose    Method = 4
	MethodHttp2ClientFrames Method = 5
	MethodHttp2ServerFrames Method = 6
)

func (m Method) String() string {
	switch m {
	case MethodUnknown:
		return "unknown"
	case MethodProduce:
		return "produce"
	case MethodConsume:
		return "consume"
	case MethodStatementPrepare:
		return "statement_prepare"
	case MethodStatementClose:
		return "statement_close"
	case MethodHttp2ClientFrames:
		return "http2_client_frames"
	case MethodHttp2ServerFrames:
		return "http2_server_frames"
	}
	return "UNKNOWN:" + strconv.Itoa(int(m))
}

type Status int

const (
	StatusUnknown Status = 0
	StatusOk      Status = 200
	StatusFailed  Status = 500
)

func (s Status) String() string {
	switch s {
	case StatusUnknown:
		return "unknown"
	case StatusOk:
		return "ok"
	case StatusFailed:
		return "failed"
	}
	return strconv.Itoa(int(s))
}

func (s Status) Http() string {
	switch {
	case s >= 100 && s < 200:
		return "1xx"
	case s >= 200 && s < 300:
		return "2xx"
	case s >= 300 && s < 400:
		return "3xx"
	case s >= 400 && s < 500:
		return "4xx"
	case s >= 500 && s < 600:
		return "5xx"
	}
	return "unknown"
}

func (s Status) DNS() string {
	switch s {
	case 0:
		return "ok"
	case 1:
		return "format_error"
	case 2:
		return "servfail"
	case 3:
		return "nxdomain"
	case 4:
		return "not_implemented"
	case 5:
		return "refused"
	}
	return ""
}

func (s Status) Zookeeper() string {
	if s <= -1 && s >= -9 {
		return "failed"
	}
	if s == -123 { //ZK_ERR_RECONFIG_DISABLED
		return "failed"
	}
	return "ok"
}

func (s Status) GRPC() string {
	switch s {
	case 0:
		return "grpc:OK"
	case 1:
		return "grpc:CANCELLED"
	case 2:
		return "grpc:UNKNOWN"
	case 3:
		return "grpc:INVALID_ARGUMENT"
	case 4:
		return "grpc:DEADLINE_EXCEEDED"
	case 5:
		return "grpc:NOT_FOUND"
	case 6:
		return "grpc:ALREADY_EXISTS"
	case 7:
		return "grpc:PERMISSION_DENIED"
	case 8:
		return "grpc:RESOURCE_EXHAUSTED"
	case 9:
		return "grpc:FAILED_PRECONDITION"
	case 10:
		return "grpc:ABORTED"
	case 11:
		return "grpc:OUT_OF_RANGE"
	case 12:
		return "grpc:UNIMPLEMENTED"
	case 13:
		return "grpc:INTERNAL"
	case 14:
		return "grpc:UNAVAILABLE"
	case 15:
		return "grpc:DATA_LOSS"
	case 16:
		return "grpc:UNAUTHENTICATED"
	}
	return ""
}

func (s Status) Error() bool {
	return s == StatusFailed
}

type RequestData struct {
	Protocol    Protocol
	Status      Status
	Duration    time.Duration
	Method      Method
	StatementId uint32
	Payload     []byte
}
