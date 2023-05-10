package tracing

import (
	"bytes"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"strconv"
	"time"
)

func handleRedisQuery(start, end time.Time, r *ebpftracer.L7Request, attrs []attribute.KeyValue) {
	cmd, args := parseRedis(r.Payload[:])
	if cmd == "" {
		return
	}
	_, span := tracer.Start(nil, cmd, trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	statement := cmd
	if args != "" {
		statement += " " + args
	}
	span.SetAttributes(append(attrs, semconv.DBSystemRedis, semconv.DBOperation(cmd), semconv.DBStatement(statement))...)
	if r.Status == 500 {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func parseRedis(payload []byte) (cmd string, args string) {
	var v, rest []byte
	var ok bool
	v, rest, ok = bytes.Cut(payload, crlf)
	if !ok || !bytes.HasPrefix(v, []byte("*")) {
		return
	}
	arrayLen, err := strconv.ParseUint(string(v[1:]), 10, 32)
	if err != nil {
		return
	}
	readString := func() string {
		v, rest, ok = bytes.Cut(rest, crlf)
		if !ok || !bytes.HasPrefix(v, []byte("$")) {
			return ""
		}
		v, rest, ok = bytes.Cut(rest, crlf)
		if ok {
			return string(v)
		}
		return ""
	}
	cmd = readString()
	if cmd == "" {
		return
	}
	if arrayLen > 1 {
		args = readString()
		if arrayLen > 2 {
			args += " ..."
		}
	}
	return
}
