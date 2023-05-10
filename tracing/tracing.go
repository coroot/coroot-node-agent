package tracing

import (
	"context"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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

var (
	tracer trace.Tracer
	space  = []byte{' '}
	crlf   = []byte{'\r', '\n'}
)

func Init(machineId, hostname, version string) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if endpoint == "" {
		klog.Infoln("no OpenTelemetry collector endpoint configured")
		return
	}
	klog.Infoln("OpenTelemetry collector endpoint:", endpoint)

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

func HandleL7Request(containerId string, dest netaddr.IPPort, r *ebpftracer.L7Request, preparedStatements map[string]string) {
	if tracer == nil {
		return
	}
	end := time.Now()
	start := end.Add(-r.Duration)

	attrs := []attribute.KeyValue{
		semconv.ContainerID(containerId),
		semconv.NetPeerName(dest.IP().String()),
		semconv.NetPeerPort(int(dest.Port())),
	}
	switch r.Protocol {
	case ebpftracer.L7ProtocolHTTP:
		handleHttpRequest(start, end, r, dest, attrs)
	case ebpftracer.L7ProtocolMemcached:
		handleMemcachedQuery(start, end, r, attrs)
	case ebpftracer.L7ProtocolRedis:
		handleRedisQuery(start, end, r, attrs)
	case ebpftracer.L7ProtocolPostgres:
		handlePostgresQuery(start, end, r, attrs, preparedStatements)
	case ebpftracer.L7ProtocolMysql:
		handleMysqlQuery(start, end, r, attrs, preparedStatements)
	case ebpftracer.L7ProtocolMongo:
		handleMongoQuery(start, end, r, attrs)
	default:
		return
	}
}
