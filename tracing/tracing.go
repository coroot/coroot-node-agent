package tracing

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"strconv"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
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
)

const (
	MemcacheDBItemKeyName attribute.Key = "db.memcached.item"
)

var (
	tracer func(containerId string) trace.Tracer
)

func Init(machineId, hostname, version string) {
	endpointUrl := *flags.TracesEndpoint
	if endpointUrl == nil {
		klog.Infoln("no OpenTelemetry traces collector endpoint configured")
		return
	}
	klog.Infoln("OpenTelemetry traces exporter endpoint:", endpointUrl.String())
	path := endpointUrl.Path
	if path == "" {
		path = "/"
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpointUrl.Host),
		otlptracehttp.WithURLPath(path),
		otlptracehttp.WithHeaders(common.AuthHeaders()),
		otlptracehttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: *flags.InsecureSkipVerify}),
	}
	if endpointUrl.Scheme != "https" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	client := otlptracehttp.NewClient(opts...)
	exporter, err := otlptrace.New(context.Background(), client) // and this exporter starts
	if err != nil {
		klog.Exitln(err)
	}

	batcher := sdktrace.WithBatcher(exporter)

	tracer = func(containerId string) trace.Tracer {
		provider := sdktrace.NewTracerProvider(
			batcher,
			sdktrace.WithResource(resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.HostName(hostname),
				semconv.HostID(machineId),
				semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
				semconv.ContainerID(containerId),
			)),
		)
		return provider.Tracer("coroot-node-agent", trace.WithInstrumentationVersion(version))
	}
}

// SpanBuilder keeps common attributes for spans
type SpanBuilder struct {
	containerId string
	destination netaddr.IPPort
	commonAttrs []attribute.KeyValue
}

func NewSpanBuilder(containerId string, destination netaddr.IPPort, rawEvent *ebpftracer.Event) *SpanBuilder {
	if tracer == nil {
		return nil
	}
	return &SpanBuilder{containerId: containerId, destination: destination, commonAttrs: []attribute.KeyValue{
		semconv.NetPeerName(destination.IP().String()),
		semconv.NetPeerPort(int(destination.Port())),
		attribute.String("tgid_req_cs", strconv.FormatUint(rawEvent.TgidReqCs, 10)),
		attribute.String("tgid_req_ss", strconv.FormatUint(rawEvent.TgidReqSs, 10)),
		attribute.String("tgid_resp_ss", strconv.FormatUint(rawEvent.TgidRespSs, 10)),
		attribute.String("tgid_resp_cs", strconv.FormatUint(rawEvent.TgidRespCs, 10)),
	}}
}

func (t *SpanBuilder) createSpan(name string, duration time.Duration, error bool, attrs ...attribute.KeyValue) {
	end := time.Now() // todo 不管之前如何滥用时间字段，这里完全在使用 process time，这一点可以使用 event time，因为中间会存在 agent 处理耗时。
	start := end.Add(-duration)
	_, span := tracer(t.containerId).Start(context.Background(), name, trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(attrs...)
	span.SetAttributes(t.commonAttrs...)
	if error {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func (t *SpanBuilder) HttpRequest(method, path string, status l7.Status, duration time.Duration) {
	if t == nil || method == "" {
		return
	}
	t.createSpan(method, duration, status >= 400,
		semconv.HTTPURL(fmt.Sprintf("http://%s%s", t.destination.String(), path)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	)
}

func (t *SpanBuilder) Http2Request(method, path, scheme string, status l7.Status, duration time.Duration) {
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

func (t *SpanBuilder) PostgresQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemPostgreSQL,
		semconv.DBStatement(query),
	)
}

func (t *SpanBuilder) MysqlQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMySQL,
		semconv.DBStatement(query),
	)
}

func (t *SpanBuilder) MongoQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMongoDB,
		semconv.DBStatement(query),
	)
}

func (t *SpanBuilder) MemcachedQuery(cmd string, items []string, error bool, duration time.Duration) {
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

func (t *SpanBuilder) RedisQuery(cmd, args string, error bool, duration time.Duration) {
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
