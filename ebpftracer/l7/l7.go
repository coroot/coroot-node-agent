package l7

import (
	"strconv"
	"time"
)

type Protocol uint8

const (
	ProtocolHTTP      Protocol = 1
	ProtocolPostgres  Protocol = 2
	ProtocolRedis     Protocol = 3
	ProtocolMemcached Protocol = 4
	ProtocolMysql     Protocol = 5
	ProtocolMongo     Protocol = 6
	ProtocolKafka     Protocol = 7
	ProtocolCassandra Protocol = 8
	ProtocolRabbitmq  Protocol = 9
	ProtocolNats      Protocol = 10
	ProtocolHTTP2     Protocol = 11
	ProtocolDubbo2    Protocol = 12
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
	return strconv.Itoa(int(s))
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
