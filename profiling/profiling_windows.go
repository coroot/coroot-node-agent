//go:build windows

package profiling

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/api"
	"github.com/coroot/coroot-node-agent/containers"
	"github.com/coroot/coroot-node-agent/flags"
	"k8s.io/klog/v2"
)

const (
	windowsProfileModeDisabled = "disabled"
	windowsProfileModeAgentCPU = "agent-cpu"
	windowsUploadTimeout       = 10 * time.Second
)

var (
	windowsEndpoint       *url.URL
	windowsHostID         string
	windowsHostName       string
	windowsProfileMode    string
	windowsProfileEvery   time.Duration
	windowsProfileFor     time.Duration
	windowsHTTPClient     = newWindowsProfileHTTPClient()
	windowsProfileLock    sync.Mutex
	windowsProfileStopCh  chan struct{}
	windowsProfileDoneCh  chan struct{}
	windowsProfileRunning bool
)

func Init(hostID, hostName string) (chan<- containers.ProcessInfo, chan *containers.ProfilingUpdate) {
	updateCh := make(chan *containers.ProfilingUpdate)

	windowsProfileLock.Lock()
	defer windowsProfileLock.Unlock()

	windowsEndpoint = *flags.ProfilesEndpoint
	windowsHostID = hostID
	windowsHostName = hostName
	windowsProfileMode = *flags.WindowsProfile
	windowsProfileEvery = normalizeWindowsProfileInterval(*flags.WindowsProfileInterval)
	windowsProfileFor = normalizeWindowsProfileDuration(*flags.WindowsProfileDuration, windowsProfileEvery)

	if windowsEndpoint == nil {
		klog.Infoln("no profiles endpoint configured")
		return nil, updateCh
	}
	if windowsProfileMode == windowsProfileModeDisabled {
		klog.Infoln("Windows profiling disabled")
		return nil, updateCh
	}
	klog.Infof("Windows profiling mode: %s, endpoint: %s", windowsProfileMode, windowsEndpoint.String())
	return nil, updateCh
}

func Start() {
	windowsProfileLock.Lock()
	if windowsEndpoint == nil || windowsProfileMode != windowsProfileModeAgentCPU || windowsProfileRunning {
		windowsProfileLock.Unlock()
		return
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	windowsProfileStopCh = stopCh
	windowsProfileDoneCh = doneCh
	windowsProfileRunning = true
	windowsProfileLock.Unlock()

	go runWindowsAgentProfiler(stopCh, doneCh)
}

func Stop() {
	windowsProfileLock.Lock()
	if !windowsProfileRunning {
		windowsProfileLock.Unlock()
		return
	}
	stopCh := windowsProfileStopCh
	doneCh := windowsProfileDoneCh
	windowsProfileRunning = false
	windowsProfileStopCh = nil
	windowsProfileDoneCh = nil
	close(stopCh)
	windowsProfileLock.Unlock()

	select {
	case <-doneCh:
	case <-time.After(windowsProfileFor + 5*time.Second):
		klog.Warningln("timed out waiting for Windows profiler to stop")
	}
}

func runWindowsAgentProfiler(stopCh <-chan struct{}, doneCh chan<- struct{}) {
	defer close(doneCh)
	collectAndUploadWindowsAgentProfile()

	ticker := time.NewTicker(windowsProfileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			collectAndUploadWindowsAgentProfile()
		}
	}
}

func collectAndUploadWindowsAgentProfile() {
	body := bytes.NewBuffer(nil)
	if err := pprof.StartCPUProfile(body); err != nil {
		klog.Warningf("failed to start Windows agent CPU profile: %s", err)
		return
	}
	time.Sleep(windowsProfileFor)
	pprof.StopCPUProfile()
	if body.Len() == 0 {
		klog.Warningln("Windows agent CPU profile was empty")
		return
	}
	if err := uploadWindowsAgentProfile(body); err != nil {
		klog.Warningf("failed to upload Windows agent CPU profile: %s", err)
	}
}

func uploadWindowsAgentProfile(body *bytes.Buffer) error {
	req, err := newWindowsProfileUploadRequest(*windowsEndpoint, windowsHostID, windowsHostName, body)
	if err != nil {
		return err
	}
	resp, err := windowsHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to upload profile %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func newWindowsProfileUploadRequest(endpoint url.URL, hostID, hostName string, body *bytes.Buffer) (*http.Request, error) {
	q := endpoint.Query()
	q.Set("host.id", hostID)
	q.Set("host.name", hostName)
	q.Set("service.name", "coroot-node-agent")
	q.Set("profile.type", "cpu")
	q.Set("profile.target", "agent")
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodPost, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	for k, v := range api.AuthHeaders(*flags.ApiKey) {
		req.Header.Set(k, v)
	}
	return req, nil
}

func normalizeWindowsProfileInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Minute
	}
	return d
}

func normalizeWindowsProfileDuration(d, interval time.Duration) time.Duration {
	if d <= 0 {
		return 10 * time.Second
	}
	if d >= interval {
		return interval / 2
	}
	return d
}

func newWindowsProfileHTTPClient() *http.Client {
	return &http.Client{
		Timeout: windowsUploadTimeout,
		Transport: &http.Transport{
			TLSClientConfig: api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify),
		},
	}
}
