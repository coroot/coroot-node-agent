package tracing

import (
	"context"
	"fmt"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
	"os"
	"time"
)

const (
	MemcacheDBItemKeyName attribute.Key = "db.memcached.item"
)

var (
	tracer trace.Tracer
)

func Init(machineId, hostname, version string) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if endpoint == "" {
		klog.Infoln("no OpenTelemetry traces collector endpoint configured")
		return
	}
	klog.Infoln("OpenTelemetry traces collector endpoint:", endpoint)

	client := otlptracehttp.NewClient()
	exporter, err := otlptrace.New(context.Background(), client)
	if err != nil {
		klog.Exitln(err)
	}
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("coroot-node-agent"),
			semconv.HostName(hostname),
			semconv.HostID(machineId),
		)),
	)
	otel.SetTracerProvider(tracerProvider)
	tracer = tracerProvider.Tracer("coroot-node-agent", trace.WithInstrumentationVersion(version))
}

type Trace struct {
	containerId string
	destination netaddr.IPPort
	commonAttrs []attribute.KeyValue
}

func NewTrace(containerId string, destination netaddr.IPPort) *Trace {
	if tracer == nil {
		return nil
	}
	return &Trace{containerId: containerId, destination: destination, commonAttrs: []attribute.KeyValue{
		semconv.ContainerID(containerId),
		semconv.NetPeerName(destination.IP().String()),
		semconv.NetPeerPort(int(destination.Port())),
	}}
}

func (t *Trace) createSpan(name string, duration time.Duration, error bool, attrs ...attribute.KeyValue) {
	end := time.Now()
	start := end.Add(-duration)
	_, span := tracer.Start(nil, name, trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(attrs...)
	span.SetAttributes(t.commonAttrs...)
	if error {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func (t *Trace) HttpRequest(method, path string, status l7.Status, duration time.Duration) {
	if t == nil || method == "" {
		return
	}
	t.createSpan(method, duration, status >= 400,
		semconv.HTTPURL(fmt.Sprintf("http://%s%s", t.destination.String(), path)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	)
}

func (t *Trace) Http2Request(method, path, scheme string, status l7.Status, duration time.Duration) {
	if t == nil {
		return
	}
	if method == "" {
		method = "unknown"
	}
	if path == "" {
		path = "/unknown"
	}
	if scheme == "" {
		scheme = "unknown"
	}
	t.createSpan(method, duration, status > 400,
		semconv.HTTPURL(fmt.Sprintf("%s://%s%s", scheme, t.destination.String(), path)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	)
}

func (t *Trace) PostgresQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemPostgreSQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MysqlQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMySQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MongoQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMongoDB,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MemcachedQuery(cmd string, items []string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	attrs := []attribute.KeyValue{
		semconv.DBSystemMemcached,
		semconv.DBOperation(cmd),
	}
	if len(items) == 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.String(items[0]))
	} else if len(items) > 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.StringSlice(items))
	}
	t.createSpan(cmd, duration, error, attrs...)
}

func (t *Trace) RedisQuery(cmd, args string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	statement := cmd
	if args != "" {
		statement += " " + args
	}
	t.createSpan(cmd, duration, error,
		semconv.DBSystemRedis,
		semconv.DBOperation(cmd),
		semconv.DBStatement(statement),
	)
}
