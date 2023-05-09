package tracing

import (
	"encoding/binary"
	"fmt"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"strconv"
	"time"
)

const (
	MysqlComQuery       = 3
	MysqlComStmtPrepare = 0x16
	MysqlComStmtExecute = 0x17
	MysqlComStmtClose   = 0x19
	mysqlMsgHeaderSize  = 4
)

func handleMysqlQuery(start, end time.Time, r *ebpftracer.L7Request, attrs []attribute.KeyValue, preparedStatements map[string]string) {
	query := parseMysql(r.Payload[:], r.StatementId, preparedStatements)
	if query == "" {
		return
	}

	_, span := tracer.Start(nil, "query", trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(append(attrs, semconv.DBSystemMySQL, semconv.DBStatement(query))...)
	if r.Status == 500 {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func parseMysql(payload []byte, statementId uint32, preparedStatements map[string]string) string {
	payloadSize := len(payload)
	if payloadSize < mysqlMsgHeaderSize+5 {
		return ""
	}
	msgSize := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16
	cmd := payload[4]
	readQuery := func() (query string) {
		to := mysqlMsgHeaderSize + msgSize
		partial := false
		if to > payloadSize-1 {
			to = payloadSize - 1
			partial = true
		}
		query = string(payload[mysqlMsgHeaderSize+1 : to])
		if partial {
			query += "..."
		}
		return query
	}
	readStatementId := func() string {
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(payload[mysqlMsgHeaderSize+1:])), 10)
	}

	switch cmd {
	case MysqlComQuery:
		return readQuery()
	case MysqlComStmtExecute:
		statementIdStr := readStatementId()
		statement, ok := preparedStatements[statementIdStr]
		if !ok {
			statement = fmt.Sprintf(`EXECUTE %s /* unknown */`, statementIdStr)
		}
		return statement
	case MysqlComStmtPrepare:
		query := readQuery()
		statementIdStr := strconv.FormatUint(uint64(statementId), 10)
		preparedStatements[statementIdStr] = query
		return fmt.Sprintf("PREPARE %s FROM %s", statementIdStr, query)
	case MysqlComStmtClose:
		statementIdStr := readStatementId()
		delete(preparedStatements, statementIdStr)
	}
	return ""
}
