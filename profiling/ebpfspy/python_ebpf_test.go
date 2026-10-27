package ebpfspy

import (
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/coroot/coroot-node-agent/profiling/pprof"
	"github.com/coroot/coroot-node-agent/profiling/symtab"
	"github.com/coroot/coroot-node-agent/profiling/testutil"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

//go:embed python_ebpf_expected.txt
var pythonEBPFExpected []byte

func pythonEBPFExpectedUbuntu() []byte {
	re := regexp.MustCompile("(?m)^python;")
	return re.ReplaceAll(pythonEBPFExpected, []byte("python3;"))
}

func TestEBPFPythonProfiler(t *testing.T) {
	// loads eBPF programs and runs Docker containers: needs root on a Linux host
	if os.Getenv("VM") == "" {
		t.Skip("set VM=1 to run")
	}
	var testdata = []struct {
		image    string
		expected []byte
	}{
		{"pyroscope/ebpf-testdata-rideshare:3.8-slim", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.9-slim", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.10-slim", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.11-slim", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.12-slim", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.13-rc-slim", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.8-alpine", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.9-alpine", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.10-alpine", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.11-alpine", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.12-alpine", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:3.13-rc-alpine", pythonEBPFExpected},
		{"pyroscope/ebpf-testdata-rideshare:ubuntu-20.04", pythonEBPFExpectedUbuntu()},
		{"pyroscope/ebpf-testdata-rideshare:ubuntu-22.04", pythonEBPFExpectedUbuntu()},
	}
	const ridesharePort = "5000"

	pullImages(t, testdata)

	for _, testdatum := range testdata {
		testdatum := testdatum
		t.Run(testdatum.image, func(t *testing.T) {

			rideshare := testutil.RunContainerWithPort(t, testdatum.image, ridesharePort)
			defer rideshare.Kill()

			profiler := startPythonProfiler(t, rideshare.ContainerID)
			defer profiler.Stop()

			loadgen(t, rideshare.Url(), 2)

			profiles := collectProfiles(t, profiler)

			compareProfiles(t, testdatum.expected, profiles)
		})
	}

}

func pullImages(t *testing.T, testdata []struct {
	image    string
	expected []byte
}) {
	wg := sync.WaitGroup{}
	for _, testdatum := range testdata {
		wg.Add(1)
		go func(img string) {
			defer wg.Done()
			testutil.PullImage(t, img)
		}(testdatum.image)
	}
	wg.Wait()
}

func compareProfiles(t *testing.T, expected []byte, actual map[string]struct{}) {
	expectedProfiles := map[string]struct{}{}
	for _, line := range strings.Split(string(expected), "\n") {
		if line == "" {
			continue
		}
		expectedProfiles[line] = struct{}{}
		t.Logf("expected: %s", line)
	}
	for line := range actual {
		t.Logf("actual: %s", line)
	}

	for profile := range expectedProfiles {
		_, ok := actual[profile]
		require.True(t, ok, fmt.Sprintf("profile %s not found in actual", profile))
	}
}

func collectProfiles(t *testing.T, profiler Session) map[string]struct{} {
	profiles := map[string]struct{}{}
	err := profiler.CollectProfiles(func(ps pprof.ProfileSample) {
		lo.Reverse(ps.Stack)
		sample := strings.Join(ps.Stack, ";")
		profiles[sample] = struct{}{}
		t.Logf("service=%s pid=%d stack=%s", ps.ServiceName, ps.Pid, sample)
	})
	require.NoError(t, err)
	return profiles
}

// containerTargetFinder profiles every process whose cgroup path contains the container id.
type containerTargetFinder struct {
	containerID string
}

func (f *containerTargetFinder) FindTarget(pid uint32) *Target {
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil || !strings.Contains(string(cg), f.containerID) {
		return nil
	}
	return &Target{ServiceName: f.containerID, ContainerID: f.containerID, Python: true}
}

func (f *containerTargetFinder) RemoveDeadPID(uint32) {}

func (f *containerTargetFinder) Reset(uint32) {}

func (f *containerTargetFinder) Update() {}

func startPythonProfiler(t *testing.T, containerID string) Session {
	options := SessionOptions{
		CollectUser:   true,
		SampleRate:    97,
		PythonEnabled: true,
		CacheOptions: symtab.CacheOptions{
			BuildIDCacheOptions: symtab.GCacheOptions{
				Size: 128, KeepRounds: 128,
			},
			SameFileCacheOptions: symtab.GCacheOptions{
				Size: 128, KeepRounds: 128,
			},
			PidCacheOptions: symtab.GCacheOptions{
				Size: 128, KeepRounds: 128,
			},
		},
	}
	s, err := NewSession(&containerTargetFinder{containerID: containerID}, options)
	require.NoError(t, err)

	err = s.Start()
	require.NoError(t, err, "Try running as privileged root user")

	impl := s.(*session)
	perf := impl.getPyPerf() // pyperf may take long time to load and verify, especially running in qemu with no kvm
	require.NotNil(t, perf)

	return s
}

func loadgen(t *testing.T, url string, n int) {
	orderVehicle := func(vehicle string) {
		url := fmt.Sprintf("%s/%s", url, vehicle)
		t.Logf("requesting %s", url)
		req, err := http.NewRequest("GET", url, nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		t.Logf("response: %s", body)
	}
	for i := 0; i < n; i++ {
		orderVehicle("bike")
		orderVehicle("car")
		orderVehicle("scooter")
		orderVehicle("cell_cls_issue")
		orderVehicle("cell_self_issue")
	}
}
