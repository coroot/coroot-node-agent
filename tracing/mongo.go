package tracing

import (
	"encoding/binary"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"go.mongodb.org/mongo-driver/bson"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"time"
)

const (
	MongoOpMSG = 2013
)

func handleMongoQuery(start, end time.Time, r *ebpftracer.L7Request, attrs []attribute.KeyValue) {
	query := parseMongo(r.Payload[:])
	if query == "" {
		return
	}
	_, span := tracer.Start(nil, "query", trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(append(attrs, semconv.DBSystemMongoDB, semconv.DBStatement(query))...)
	if r.Status == 500 {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

const (
	mongoHeaderLength      = 20
	mongoOpCodeOffset      = 12
	mongoSectionKindLength = 1
	mongoSectionSizeLength = 4
	mongoSectionKindBody   = 0
)

func parseMongo(payload []byte) (res string) {
	res = "<truncated>"
	if len(payload) < mongoHeaderLength+mongoSectionKindLength+mongoSectionSizeLength {
		return
	}
	opCode := binary.LittleEndian.Uint32(payload[mongoOpCodeOffset:])
	if opCode != MongoOpMSG {
		return
	}
	sectionKind := payload[mongoHeaderLength]
	if sectionKind != mongoSectionKindBody {
		return
	}
	sectionData := payload[mongoHeaderLength+mongoSectionKindLength:]
	sectionLength := binary.LittleEndian.Uint32(sectionData)
	if sectionLength < 1 || int(sectionLength) > len(sectionData) {
		return
	}
	return bson.Raw(sectionData).String()
}
