package logs

import (
	"context"
	"crypto/tls"
	"net/url"
	"strings"
	"time"

	otel "github.com/agoda-com/opentelemetry-logs-go"
	"github.com/agoda-com/opentelemetry-logs-go/exporters/otlp/otlplogs"
	"github.com/agoda-com/opentelemetry-logs-go/exporters/otlp/otlplogs/otlplogshttp"
	otelLogs "github.com/agoda-com/opentelemetry-logs-go/logs"
	sdk "github.com/agoda-com/opentelemetry-logs-go/sdk/logs"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/logparser"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

// MultilineCollectorTimeout is how long the log parser waits before deciding a
// multi-line log message is complete.
const MultilineCollectorTimeout = time.Second

func PatternExtractionRateLimiter() *rate.Limiter {
	limit := *flags.LogPatternExtractionLimit
	if limit <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(limit), int(limit*10))
}

type Config struct {
	Endpoint    *url.URL
	AuthHeaders map[string]string
	TLSConfig   *tls.Config
}

var (
	loggerProvider *sdk.LoggerProvider
	otelLogger     otelLogs.Logger
)

func Init(cfg Config, machineId, hostname, version string) {
	if cfg.Endpoint == nil {
		klog.Infoln("no OpenTelemetry logs collector endpoint configured")
		return
	}
	klog.Infoln("OpenTelemetry logs collector endpoint:", cfg.Endpoint.String())
	path := cfg.Endpoint.Path
	if path == "" {
		path = "/"
	}

	opts := []otlplogshttp.Option{
		otlplogshttp.WithEndpoint(cfg.Endpoint.Host),
		otlplogshttp.WithURLPath(path),
		otlplogshttp.WithHeaders(cfg.AuthHeaders),
	}
	if cfg.Endpoint.Scheme == "https" {
		opts = append(opts, otlplogshttp.WithTLSClientConfig(cfg.TLSConfig))
	} else {
		opts = append(opts, otlplogshttp.WithInsecure())
	}
	client := otlplogshttp.NewClient(opts...)
	exporter, _ := otlplogs.NewExporter(context.Background(), otlplogs.WithClient(client))

	loggerProvider = sdk.NewLoggerProvider(
		sdk.WithBatcher(exporter),
		sdk.WithResource(
			resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceName("coroot-node-agent"),
				semconv.HostName(hostname),
				semconv.HostID(machineId),
			),
		),
	)
	otel.SetLoggerProvider(loggerProvider)
	otelLogger = loggerProvider.Logger("coroot-node-agent", otelLogs.WithInstrumentationVersion(version))
}

func Shutdown(ctx context.Context) {
	if loggerProvider != nil {
		_ = loggerProvider.Shutdown(ctx)
	}
}

const (
	traceIdKey = "traceid"
	spanIdKey  = "spanid"
)

var (
	traceIdKeys = []string{traceIdKey, "trace_id", "trace-id", "trace.id"}
	spanIdKeys  = []string{spanIdKey, "span_id", "span-id", "span.id"}
)

func normalizeTraceContextKey(k string) string {
	k = strings.ToLower(k)
	switch k {
	case "@tr":
		return traceIdKey
	case "@sp":
		return spanIdKey
	}
	if strings.Contains(k, "parent") { // e.g. parent_span_id is not the record's span id
		return ""
	}
	for _, s := range traceIdKeys {
		if k == s || strings.HasSuffix(k, "."+s) {
			return traceIdKey
		}
	}
	for _, s := range spanIdKeys {
		if k == s || strings.HasSuffix(k, "."+s) {
			return spanIdKey
		}
	}
	return ""
}

func logRecordAttrs(source, patternHash string, attributes map[string]string) ([]attribute.KeyValue, *trace.TraceID, *trace.SpanID) {
	var traceId *trace.TraceID
	var spanId *trace.SpanID
	attrs := make([]attribute.KeyValue, 0, len(attributes)+2)
	attrs = append(attrs, attribute.Key("pattern.hash").String(patternHash))
	if source != "" {
		attrs = append(attrs, attribute.Key(LogSourceAttribute).String(source))
	}
	for k, v := range attributes {
		switch normalizeTraceContextKey(k) {
		case traceIdKey:
			if traceId == nil {
				if id, err := trace.TraceIDFromHex(strings.ToLower(v)); err == nil {
					traceId = &id
					continue
				}
			}
		case spanIdKey:
			if spanId == nil {
				if id, err := trace.SpanIDFromHex(strings.ToLower(v)); err == nil {
					spanId = &id
					continue
				}
			}
		}
		attrs = append(attrs, attribute.Key(k).String(v))
	}
	return attrs, traceId, spanId
}

const LogSourceAttribute = "log.source"

func OtelLogEmitter(containerId, source string) logparser.OnMsgCallbackF {
	if otelLogger == nil {
		return nil
	}
	return func(ts time.Time, level logparser.Level, patternHash string, msg string, attributes map[string]string) {
		severityText := level.String()
		severityNumber := otelLogs.UNSPECIFIED
		switch level {
		case logparser.LevelCritical:
			severityNumber = otelLogs.FATAL
		case logparser.LevelError:
			severityNumber = otelLogs.ERROR
		case logparser.LevelWarning:
			severityNumber = otelLogs.WARN
		case logparser.LevelInfo:
			severityNumber = otelLogs.INFO
		case logparser.LevelDebug:
			severityNumber = otelLogs.DEBUG
		}

		attrs, traceId, spanId := logRecordAttrs(source, patternHash, attributes)

		otelLogger.Emit(
			otelLogs.NewLogRecord(otelLogs.LogRecordConfig{
				ObservedTimestamp: ts,
				TraceId:           traceId,
				SpanId:            spanId,
				SeverityText:      &severityText,
				SeverityNumber:    &severityNumber,
				Body:              &msg,
				Resource: resource.NewSchemaless(
					semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
					semconv.ContainerID(containerId),
				),
				Attributes: &attrs,
			}),
		)
	}
}
