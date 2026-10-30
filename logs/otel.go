package logs

import (
	"context"
	"crypto/tls"
	"net/url"
	"strings"
	"time"

	cacommon "github.com/coroot/coroot-cluster-agent/common"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/logparser"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
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
	exporter      *cacommon.LogsPipeline
	resourceAttrs []attribute.KeyValue
)

func Init(cfg Config, machineId, hostname, version string) {
	if cfg.Endpoint == nil {
		klog.Infoln("no OpenTelemetry logs collector endpoint configured")
		return
	}
	klog.Infoln("OpenTelemetry logs collector endpoint:", cfg.Endpoint.String())
	p, err := cacommon.NewLogsPipeline(cfg.Endpoint, cfg.AuthHeaders, cfg.TLSConfig)
	if err != nil {
		klog.Errorln("failed to create the OpenTelemetry logs exporter, logs won't be sent:", err)
		return
	}
	exporter = p
	resourceAttrs = []attribute.KeyValue{semconv.HostName(hostname), semconv.HostID(machineId)}
}

func Exporter() *cacommon.LogsPipeline {
	return exporter
}

func Shutdown(ctx context.Context) {
	_ = exporter.Shutdown(ctx)
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

func logRecordAttrs(source, patternHash string, attributes map[string]string) ([]log.KeyValue, trace.SpanContext) {
	var traceId trace.TraceID
	var spanId trace.SpanID
	for k, v := range attributes {
		switch normalizeTraceContextKey(k) {
		case traceIdKey:
			if !traceId.IsValid() {
				traceId, _ = trace.TraceIDFromHex(strings.ToLower(v))
			}
		case spanIdKey:
			if !spanId.IsValid() {
				spanId, _ = trace.SpanIDFromHex(strings.ToLower(v))
			}
		}
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceId, SpanID: spanId})
	attrs := make([]log.KeyValue, 0, len(attributes)+2)
	attrs = append(attrs, log.String("pattern.hash", patternHash))
	if source != "" {
		attrs = append(attrs, log.String(LogSourceAttribute, source))
	}
	for k, v := range attributes {
		if sc.IsValid() && normalizeTraceContextKey(k) != "" {
			continue
		}
		attrs = append(attrs, log.String(k, v))
	}
	return attrs, sc
}

const LogSourceAttribute = "log.source"

func OtelLogEmitter(containerId, source string) logparser.OnMsgCallbackF {
	if exporter == nil {
		return nil
	}
	attrs := append([]attribute.KeyValue{semconv.ContainerID(containerId)}, resourceAttrs...)
	provider, err := exporter.NewLoggerProvider(common.ContainerIdToOtelServiceName(containerId), attrs...)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	// No instrumentation scope: Coroot stores the scope name and version as two extra attributes on every record.
	logger := provider.Logger("")
	return func(ts time.Time, level logparser.Level, patternHash string, msg string, attributes map[string]string) {
		attrs, sc := logRecordAttrs(source, patternHash, attributes)
		record := log.Record{}
		record.SetTimestamp(ts)
		record.SetObservedTimestamp(ts)
		record.SetSeverityText(level.String())
		record.SetSeverity(cacommon.LogSeverity(level))
		record.SetBody(log.StringValue(msg))
		record.AddAttributes(attrs...)
		ctx := context.Background()
		if sc.IsValid() {
			ctx = trace.ContextWithSpanContext(ctx, sc)
		}
		logger.Emit(ctx, record)
	}
}
