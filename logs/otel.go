package logs

import (
	"context"
	"crypto/tls"
	"net/url"
	"time"

	otel "github.com/agoda-com/opentelemetry-logs-go"
	"github.com/agoda-com/opentelemetry-logs-go/exporters/otlp/otlplogs"
	"github.com/agoda-com/opentelemetry-logs-go/exporters/otlp/otlplogs/otlplogshttp"
	otelLogs "github.com/agoda-com/opentelemetry-logs-go/logs"
	sdk "github.com/agoda-com/opentelemetry-logs-go/sdk/logs"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/logparser"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"k8s.io/klog/v2"
)

// MultilineCollectorTimeout is how long the log parser waits before deciding a
// multi-line log message is complete.
const MultilineCollectorTimeout = time.Second

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
		otlplogshttp.WithTLSClientConfig(cfg.TLSConfig),
	}
	if cfg.Endpoint.Scheme != "https" {
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

func OtelLogEmitter(containerId string) logparser.OnMsgCallbackF {
	if otelLogger == nil {
		return nil
	}
	return func(ts time.Time, level logparser.Level, patternHash string, msg string) {
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

		otelLogger.Emit(
			otelLogs.NewLogRecord(otelLogs.LogRecordConfig{
				ObservedTimestamp: ts,
				SeverityText:      &severityText,
				SeverityNumber:    &severityNumber,
				Body:              &msg,
				Resource: resource.NewSchemaless(
					semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
					semconv.ContainerID(containerId),
				),
				Attributes: &[]attribute.KeyValue{
					attribute.Key("pattern.hash").String(patternHash),
				},
			}),
		)
	}
}
