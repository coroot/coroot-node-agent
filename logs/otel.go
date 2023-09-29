package logs

import (
	"context"
	otel "github.com/agoda-com/opentelemetry-logs-go"
	"github.com/agoda-com/opentelemetry-logs-go/exporters/otlp/otlplogs"
	"github.com/agoda-com/opentelemetry-logs-go/exporters/otlp/otlplogs/otlplogshttp"
	otelLogs "github.com/agoda-com/opentelemetry-logs-go/logs"
	sdk "github.com/agoda-com/opentelemetry-logs-go/sdk/logs"
	"github.com/coroot/logparser"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"k8s.io/klog/v2"
	"os"
	"time"
)

var otelLogger otelLogs.Logger

func Init(machineId, hostname, version string) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
	if endpoint == "" {
		klog.Infoln("no OpenTelemetry logs collector endpoint configured")
		return
	}
	klog.Infoln("OpenTelemetry logs collector endpoint:", endpoint)

	exporter, _ := otlplogs.NewExporter(context.Background(), otlplogs.WithClient(otlplogshttp.NewClient()))
	loggerProvider := sdk.NewLoggerProvider(
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
				Attributes: &[]attribute.KeyValue{
					semconv.ContainerID(containerId),
					attribute.Key("pattern.hash").String(patternHash),
				},
			}),
		)
	}
}
