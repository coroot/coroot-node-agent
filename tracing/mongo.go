package tracing

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"go.mongodb.org/mongo-driver/bson"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"io"
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

type mongoMsgHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

func parseMongo(payload []byte) string {
	h := &mongoMsgHeader{}
	reader := bufio.NewReader(bytes.NewReader(payload))
	if err := binary.Read(reader, binary.LittleEndian, h); err != nil {
		return ""
	}
	if h.OpCode != MongoOpMSG {
		return ""
	}
	if _, err := reader.Discard(4); err != nil { //flagBits
		return ""
	}
	if sectionKind, err := reader.ReadByte(); err != nil || sectionKind != 0 {
		return ""
	}
	return bsonToString(reader)
}

func bsonToString(r io.Reader) (res string) {
	res = "<truncated>"
	defer func() {
		recover()
	}()
	if raw, err := bson.NewFromIOReader(r); err == nil {
		res = raw.String()
	}
	return
}
