package tracing

import (
	"bytes"
	"fmt"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"time"
)

const (
	PostgresFrameQuery byte = 'Q'
	PostgresFrameBind  byte = 'B'
	PostgresFrameParse byte = 'P'
	PostgresFrameClose byte = 'C'
)

func handlePostgresQuery(start, end time.Time, r *ebpftracer.L7Request, attrs []attribute.KeyValue, preparedStatements map[string]string) {
	query := parsePostgres(r.Payload[:], preparedStatements)
	if query == "" {
		return
	}
	_, span := tracer.Start(nil, "query", trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(append(attrs, semconv.DBSystemPostgreSQL, semconv.DBStatement(query))...)
	if r.Status == 500 {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func parsePostgres(payload []byte, preparedStatements map[string]string) string {
	l := len(payload)
	if l < 5 {
		return ""
	}
	cmd := payload[0]
	switch cmd {
	case PostgresFrameQuery:
		var query string
		if q, _, ok := bytes.Cut(payload[5:], []byte{0}); ok {
			query = string(q)
		} else {
			query = string(q) + "..."
		}
		return query
	case PostgresFrameBind:
		_, rest, ok := bytes.Cut(payload[5:], []byte{0})
		if !ok {
			return ""
		}
		preparedStatementName, _, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return ""
		}
		preparedStatementNameStr := string(preparedStatementName)
		statement, ok := preparedStatements[preparedStatementNameStr]
		if !ok {
			statement = fmt.Sprintf(`EXECUTE %s /* unknown */`, preparedStatementNameStr)
		}
		return statement
	case PostgresFrameParse:
		preparedStatementName, rest, ok := bytes.Cut(payload[5:], []byte{0})
		if !ok {
			return ""
		}
		var query string
		q, _, ok := bytes.Cut(rest, []byte{0})
		if ok {
			query = string(q)
		} else {
			query = string(q) + "..."
		}
		preparedStatementNameStr := string(preparedStatementName)
		preparedStatements[preparedStatementNameStr] = query
		return fmt.Sprintf("PREPARE %s AS %s", preparedStatementNameStr, query)
	case PostgresFrameClose:
		if l < 7 {
			return ""
		}
		if payload[5] != 'S' {
			return ""
		}
		preparedStatementName, _, ok := bytes.Cut(payload[6:], []byte{0})
		if !ok {
			return ""
		}
		delete(preparedStatements, string(preparedStatementName))
	}
	return ""
}
