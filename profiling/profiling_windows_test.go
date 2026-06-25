//go:build windows

package profiling

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/flags"
)

func TestWindowsProfilingDefaultDisabledContract(t *testing.T) {
	resetWindowsProfilingForTest(t)
	processInfoCh, updateCh := Init("host-id", "host-name")
	if processInfoCh != nil {
		t.Fatal("Windows agent self profiling should not consume process info")
	}
	if updateCh == nil {
		t.Fatal("Windows profiling must return a non-nil update channel")
	}
	Start()
	Stop()
}

func TestWindowsProfileUploadRequest(t *testing.T) {
	endpoint, err := url.Parse("http://collector.example/v1/profiles")
	if err != nil {
		t.Fatal(err)
	}
	req, err := newWindowsProfileUploadRequest(*endpoint, "host-id", "host-name", bytes.NewBufferString("profile"))
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("method=%s, want POST", req.Method)
	}
	q := req.URL.Query()
	expected := map[string]string{
		"host.id":        "host-id",
		"host.name":      "host-name",
		"service.name":   "coroot-node-agent",
		"profile.type":   "cpu",
		"profile.target": "agent",
	}
	for k, v := range expected {
		if got := q.Get(k); got != v {
			t.Fatalf("query %s=%q, want %q", k, got, v)
		}
	}
}

func TestWindowsAgentCPUProfileUpload(t *testing.T) {
	resetWindowsProfilingForTest(t)
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if len(body) == 0 {
			t.Error("empty profile body")
		}
		if got := r.URL.Query().Get("service.name"); got != "coroot-node-agent" {
			t.Errorf("service.name=%q, want coroot-node-agent", got)
		}
		received <- r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	endpoint, err := url.Parse(server.URL + "/v1/profiles")
	if err != nil {
		t.Fatal(err)
	}
	withWindowsProfilingFlags(t, endpoint, windowsProfileModeAgentCPU, time.Hour, 100*time.Millisecond)

	Init("host-id", "host-name")
	Start()
	defer Stop()

	select {
	case query := <-received:
		if query == "" {
			t.Fatal("profile upload query is empty")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("profile upload was not received")
	}
}

func withWindowsProfilingFlags(t *testing.T, endpoint *url.URL, mode string, interval, duration time.Duration) {
	t.Helper()
	oldEndpoint := *flags.ProfilesEndpoint
	oldMode := *flags.WindowsProfile
	oldInterval := *flags.WindowsProfileInterval
	oldDuration := *flags.WindowsProfileDuration
	*flags.ProfilesEndpoint = endpoint
	*flags.WindowsProfile = mode
	*flags.WindowsProfileInterval = interval
	*flags.WindowsProfileDuration = duration
	t.Cleanup(func() {
		*flags.ProfilesEndpoint = oldEndpoint
		*flags.WindowsProfile = oldMode
		*flags.WindowsProfileInterval = oldInterval
		*flags.WindowsProfileDuration = oldDuration
	})
}

func resetWindowsProfilingForTest(t *testing.T) {
	t.Helper()
	Stop()
	windowsProfileLock.Lock()
	defer windowsProfileLock.Unlock()
	windowsEndpoint = nil
	windowsHostID = ""
	windowsHostName = ""
	windowsProfileMode = windowsProfileModeDisabled
	windowsProfileEvery = time.Minute
	windowsProfileFor = 10 * time.Second
	windowsHTTPClient = newWindowsProfileHTTPClient()
	windowsProfileStopCh = nil
	windowsProfileDoneCh = nil
	windowsProfileRunning = false
}
