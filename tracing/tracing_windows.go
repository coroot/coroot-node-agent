package tracing

import (
	"context"
	"net/url"
	"time"

	"github.com/coroot/coroot-node-agent/api"
	"github.com/coroot/coroot-node-agent/flags"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/klog/v2"
)

var (
	traceProvider *sdktrace.TracerProvider
	agentTracer   trace.Tracer
	initialized   bool
	samplingRate  float64
)

func Init(machineID, hostname, version string) {
	endpointURL := *flags.TracesEndpoint
	if endpointURL == nil {
		klog.Infoln("no OpenTelemetry traces collector endpoint configured")
		return
	}

	samplingRate = normalizeSamplingRate(*flags.TracesSampling)
	if samplingRate < 1.0 {
		klog.Infof("trace sampling rate set to %f", samplingRate)
	}
	klog.Infoln("OpenTelemetry traces collector endpoint:", endpointURL.String())

	exporter, err := newTraceExporter(endpointURL)
	if err != nil {
		klog.Exitln(err)
	}
	traceProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(samplingRate)),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("coroot-node-agent"),
			semconv.HostName(hostname),
			semconv.HostID(machineID),
			attribute.String("os.type", "windows"),
		)),
	)
	otel.SetTracerProvider(traceProvider)
	agentTracer = traceProvider.Tracer("coroot-node-agent", trace.WithInstrumentationVersion(version))
	initialized = true
	emitLifecycleSpan("coroot-node-agent.start")
}

func normalizeSamplingRate(value float64) float64 {
	if value < 0.0 || value > 1.0 {
		klog.Warningf("invalid traces-sampling value %f, must be between 0.0 and 1.0, using default 1.0", value)
		return 1.0
	}
	return value
}

func newTraceExporter(endpointURL *url.URL) (*otlptrace.Exporter, error) {
	path := endpointURL.Path
	if path == "" {
		path = "/"
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpointURL.Host),
		otlptracehttp.WithURLPath(path),
		otlptracehttp.WithHeaders(api.AuthHeaders(*flags.ApiKey)),
		otlptracehttp.WithTLSClientConfig(api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify)),
	}
	if endpointURL.Scheme != "https" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	client := otlptracehttp.NewClient(opts...)
	return otlptrace.New(context.Background(), client)
}

func emitLifecycleSpan(name string) {
	if agentTracer == nil {
		return
	}
	_, span := agentTracer.Start(context.Background(), name, trace.WithSpanKind(trace.SpanKindInternal))
	span.End()
	if traceProvider == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := traceProvider.ForceFlush(ctx); err != nil {
		klog.Warningf("failed to flush Windows lifecycle trace: %s", err)
	}
}
