package tracing

import (
	"context"
	"testing"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	collectorpb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// cutMidRune is a payload sliced inside a multi-byte rune, the same shape as
// MaxPayloadSize truncating a UTF-8 statement.
func cutMidRune(s string, n int) string {
	b := []byte(s)
	if n < 0 || n > len(b) {
		panic("cutMidRune: n out of range")
	}
	return string(b[:n])
}

func TestInvalidUTF8AttributeDoesNotRejectOTLPBatch(t *testing.T) {
	prev := samplingRate
	samplingRate = 1
	t.Cleanup(func() { samplingRate = prev })

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	// "SELECT 'я'" is 11 bytes; byte 9 is the first half of я (U+044F).
	badQuery := cutMidRune("SELECT 'я'", 9)
	// "ключ"[:3] ends on the first byte of л.
	badKey := cutMidRune("ключ", 3)
	badHost := string([]byte{0xff, 'd', 'b'})
	badCmd := "GE" + string([]byte{0xc3})
	if utf8.ValidString(badQuery) || utf8.ValidString(badKey) || utf8.ValidString(badHost) || utf8.ValidString(badCmd) {
		t.Fatal("fixtures must be invalid UTF-8")
	}

	tr := &Trace{
		tracer: &Tracer{otel: tp.Tracer("coroot-node-agent")},
		commonAttrs: []attribute.KeyValue{
			attribute.String("net.peer.name", badHost),
			attribute.Int("net.peer.port", 5432),
		},
	}

	const validQuery = "SELECT 'я'"
	tr.PostgresQuery(validQuery, false, time.Millisecond)
	tr.PostgresQuery(badQuery, false, time.Millisecond)
	tr.MemcachedQuery("get", []string{"session", badKey, "я"}, false, time.Millisecond)
	tr.RedisQuery(badCmd, "user:1", false, time.Millisecond)

	spans := rec.Ended()
	if len(spans) != 4 {
		t.Fatalf("recorded %d spans, want 4 (a sibling span must stay in the batch)", len(spans))
	}

	req := otlpRequest(spans)
	if _, err := proto.Marshal(req); err != nil {
		t.Fatalf("OTLP batch marshal: %v", err)
	}

	valid := spanByStatement(t, spans, validQuery)
	if got := attrString(t, valid, "db.statement"); got != validQuery {
		t.Fatalf("valid UTF-8 statement = %q", got)
	}
	if got := attrInt(t, valid, "net.peer.port"); got != 5432 {
		t.Fatalf("net.peer.port = %d", got)
	}
	if got := attrString(t, valid, "net.peer.name"); got != "\uFFFDdb" {
		t.Fatalf("net.peer.name = %q", got)
	}

	broken := spanByStatementPrefix(t, spans, "SELECT '")
	if broken == valid {
		t.Fatal("truncated statement was not recorded separately")
	}
	if got := attrString(t, broken, "db.statement"); got != "SELECT '\uFFFD" {
		t.Fatalf("truncated statement = %q", got)
	}

	mem := spanByName(t, spans, "get")
	items := attrStringSlice(t, mem, "db.memcached.item")
	if len(items) != 3 || items[0] != "session" || items[1] != "к\uFFFD" || items[2] != "я" {
		t.Fatalf("memcached items = %#v", items)
	}

	redis := spanByName(t, spans, "GE\uFFFD")
	if got := attrString(t, redis, "db.operation"); got != "GE\uFFFD" {
		t.Fatalf("db.operation = %q", got)
	}
	if got := attrString(t, redis, "db.statement"); got != "GE\uFFFD user:1" {
		t.Fatalf("redis statement = %q", got)
	}
}

func otlpRequest(spans []sdktrace.ReadOnlySpan) *collectorpb.ExportTraceServiceRequest {
	pbSpans := make([]*tracepb.Span, 0, len(spans))
	for _, sp := range spans {
		ps := &tracepb.Span{Name: sp.Name()}
		for _, a := range sp.Attributes() {
			kv := &commonpb.KeyValue{Key: string(a.Key)}
			switch a.Value.Type() {
			case attribute.STRING:
				kv.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: a.Value.AsString()}}
			case attribute.INT64:
				kv.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: a.Value.AsInt64()}}
			case attribute.STRINGSLICE:
				vals := make([]*commonpb.AnyValue, 0, len(a.Value.AsStringSlice()))
				for _, item := range a.Value.AsStringSlice() {
					vals = append(vals, &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: item}})
				}
				kv.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: vals}}}
			default:
				continue
			}
			ps.Attributes = append(ps.Attributes, kv)
		}
		pbSpans = append(pbSpans, ps)
	}
	return &collectorpb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: pbSpans}},
		}},
	}
}

func spanByName(t *testing.T, spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	for _, sp := range spans {
		if sp.Name() == name {
			return sp
		}
	}
	t.Fatalf("no span named %q", name)
	return nil
}

func spanByStatement(t *testing.T, spans []sdktrace.ReadOnlySpan, statement string) sdktrace.ReadOnlySpan {
	t.Helper()
	for _, sp := range spans {
		if attrString(t, sp, "db.statement") == statement {
			return sp
		}
	}
	t.Fatalf("no span with db.statement %q", statement)
	return nil
}

func spanByStatementPrefix(t *testing.T, spans []sdktrace.ReadOnlySpan, prefix string) sdktrace.ReadOnlySpan {
	t.Helper()
	for _, sp := range spans {
		got := attrString(t, sp, "db.statement")
		if len(got) >= len(prefix) && got[:len(prefix)] == prefix && got != "SELECT 'я'" {
			return sp
		}
	}
	t.Fatalf("no truncated statement with prefix %q", prefix)
	return nil
}

func attrString(t *testing.T, sp sdktrace.ReadOnlySpan, key string) string {
	t.Helper()
	for _, a := range sp.Attributes() {
		if string(a.Key) == key && a.Value.Type() == attribute.STRING {
			return a.Value.AsString()
		}
	}
	t.Fatalf("span %q missing string attribute %s", sp.Name(), key)
	return ""
}

func attrInt(t *testing.T, sp sdktrace.ReadOnlySpan, key string) int64 {
	t.Helper()
	for _, a := range sp.Attributes() {
		if string(a.Key) == key && a.Value.Type() == attribute.INT64 {
			return a.Value.AsInt64()
		}
	}
	t.Fatalf("span %q missing int attribute %s", sp.Name(), key)
	return 0
}

func attrStringSlice(t *testing.T, sp sdktrace.ReadOnlySpan, key string) []string {
	t.Helper()
	for _, a := range sp.Attributes() {
		if string(a.Key) == key && a.Value.Type() == attribute.STRINGSLICE {
			return a.Value.AsStringSlice()
		}
	}
	t.Fatalf("span %q missing string slice %s", sp.Name(), key)
	return nil
}
