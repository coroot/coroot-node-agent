package tracing

import (
	"bytes"
	"fmt"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"inet.af/netaddr"
	"time"
)

func handleHttpRequest(start, end time.Time, r *ebpftracer.L7Request, dest netaddr.IPPort, attrs []attribute.KeyValue) {
	method, path := parseHttp(r.Payload[:])
	if method == "" {
		return
	}
	_, span := tracer.Start(nil, method, trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(append(
		attrs,
		semconv.HTTPURL(fmt.Sprintf("http://%s%s", dest.String(), path)),
		semconv.HTTPMethod(method),
		semconv.HTTPSchemeHTTP,
		semconv.HTTPStatusCode(r.Status),
	)...)
	if r.Status >= 400 {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func parseHttp(payload []byte) (string, string) {
	// the HTTP method is being validated in the eBPF code, confirming that the request is an HTTP request
	method, rest, ok := bytes.Cut(payload, space)
	if !ok {
		return "", ""
	}
	uri, _, ok := bytes.Cut(rest, space)
	if !ok {
		uri = append(uri, []byte("...")...)
	}
	return string(method), string(uri)
}
