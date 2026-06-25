//go:build windows

package tracing

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/flags"
)

func TestWindowsInitWithoutEndpointIsNoop(t *testing.T) {
	resetWindowsTracingForTest(t)
	oldEndpoint := *flags.TracesEndpoint
	*flags.TracesEndpoint = nil
	defer func() { *flags.TracesEndpoint = oldEndpoint }()

	Init("machine-id", "host", "test")

	if initialized {
		t.Fatal("Init initialized tracing with nil endpoint")
	}
}

func TestNormalizeSamplingRate(t *testing.T) {
	cases := []struct {
		value float64
		want  float64
	}{
		{value: -0.1, want: 1.0},
		{value: 0.0, want: 0.0},
		{value: 0.25, want: 0.25},
		{value: 1.0, want: 1.0},
		{value: 1.1, want: 1.0},
	}
	for _, tc := range cases {
		if got := normalizeSamplingRate(tc.value); got != tc.want {
			t.Fatalf("normalizeSamplingRate(%f)=%f, want %f", tc.value, got, tc.want)
		}
	}
}

func TestWindowsInitEmitsLifecycleSpan(t *testing.T) {
	resetWindowsTracingForTest(t)
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			t.Errorf("path=%q, want /v1/traces", r.URL.Path)
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if len(payload) == 0 {
			t.Error("empty OTLP trace payload")
		}
		select {
		case received <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	endpoint, err := url.Parse(server.URL + "/v1/traces")
	if err != nil {
		t.Fatal(err)
	}
	oldEndpoint := *flags.TracesEndpoint
	oldSampling := *flags.TracesSampling
	*flags.TracesEndpoint = endpoint
	*flags.TracesSampling = 1.0
	defer func() {
		*flags.TracesEndpoint = oldEndpoint
		*flags.TracesSampling = oldSampling
	}()

	Init("machine-id", "host", "test")

	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("OTLP trace receiver did not receive lifecycle span")
	}
}

func resetWindowsTracingForTest(t *testing.T) {
	t.Helper()
	if traceProvider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = traceProvider.Shutdown(ctx)
		cancel()
	}
	traceProvider = nil
	agentTracer = nil
	initialized = false
	samplingRate = 0
}
