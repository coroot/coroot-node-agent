package tracing

import (
	"bytes"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"strings"
	"time"
)

const (
	MemcacheDBItemKeyName attribute.Key = "db.memcached.item"
)

func handleMemcachedQuery(start, end time.Time, r *ebpftracer.L7Request, attrs []attribute.KeyValue) {
	cmd, items := parseMemcached(r.Payload[:])
	if cmd == "" {
		return
	}
	_, span := tracer.Start(nil, cmd, trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	if len(items) == 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.String(items[0]))
	} else if len(items) > 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.StringSlice(items))
	}
	span.SetAttributes(append(attrs, semconv.DBSystemMemcached, semconv.DBOperation(cmd))...)
	if r.Status == 500 {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func parseMemcached(payload []byte) (string, []string) {
	cmd, rest, ok := bytes.Cut(payload, space)
	if !ok {
		return "", nil
	}
	command := string(cmd)
	switch command {
	case "set", "add", "cas", "append", "prepend", "replace", "delete", "incr", "decr", "touch":
		if key, _, ok := bytes.Cut(rest, space); ok {
			return command, []string{string(key)}
		}
	case "gat", "gats":
		_, rest, ok = bytes.Cut(rest, space)
		if ok {
			keys, _, ok := bytes.Cut(rest, crlf)
			if ok {
				return command, strings.Split(string(keys), " ")
			}
		}
	case "get", "gets":
		keys, _, ok := bytes.Cut(rest, crlf)
		if ok {
			return command, strings.Split(string(keys), " ")
		}
	}
	return "", nil
}
