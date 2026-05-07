package gpu

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseNsightMetricsCSV(t *testing.T) {
	collectedAt := time.Unix(10, 0)
	payload := []byte(`gpu_uuid,gpu_utilization_avg,gpu_utilization_peak,memory_utilization_avg,memory_utilization_peak,compute_occupancy_avg,compute_occupancy_peak
63c0bd08-6466-9b69-bf0e-06388b78bfe3,12.5,35,4.25,10,3.5,7
GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee,0,1,2,3,4,5
`)

	metrics, err := parseNsightMetricsCSV(payload, collectedAt)
	require.NoError(t, err)
	require.Len(t, metrics, 2)

	m := metrics["GPU-63c0bd08-6466-9b69-bf0e-06388b78bfe3"]
	require.Equal(t, 12.5, m.GPUUtilizationAvg)
	require.Equal(t, float64(35), m.GPUUtilizationPeak)
	require.Equal(t, 4.25, m.MemoryUtilizationAvg)
	require.Equal(t, float64(10), m.MemoryUtilizationPeak)
	require.Equal(t, 3.5, m.ComputeOccupancyAvg)
	require.Equal(t, float64(7), m.ComputeOccupancyPeak)
	require.Equal(t, collectedAt, m.CollectedAt)

	require.Contains(t, metrics, "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
}

func TestParseNsightMetricsCSVAllowsMissingValues(t *testing.T) {
	payload := []byte(`gpu_uuid,gpu_utilization_avg,gpu_utilization_peak,memory_utilization_avg,memory_utilization_peak,compute_occupancy_avg,compute_occupancy_peak
63c0bd08-6466-9b69-bf0e-06388b78bfe3,,,,,,
`)

	metrics, err := parseNsightMetricsCSV(payload, time.Now())
	require.NoError(t, err)
	require.Equal(t, float64(0), metrics["GPU-63c0bd08-6466-9b69-bf0e-06388b78bfe3"].GPUUtilizationAvg)
}

func TestNewNsightCollectorRequiresNvidiaGPU(t *testing.T) {
	c, err := newNsightCollector(nil)
	require.Nil(t, c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no NVIDIA GPUs detected")
}

func TestNsightCommandPathForHostNsight(t *testing.T) {
	hostNsys := "/proc/1/root/opt/nvidia/nsight-systems/2025.6.3/target-linux-x64/nsys"

	require.True(t, nsightRunsOnHost(hostNsys))
	require.Equal(t, "/opt/nvidia/nsight-systems/2025.6.3/target-linux-x64/nsys", nsightCommandPath(hostNsys, hostNsys))
	require.Equal(t, "/tmp/coroot-nsys-123/gpu", nsightCommandPath(hostNsys, "/proc/1/root/tmp/coroot-nsys-123/gpu"))
	require.Equal(t, "/tmp/coroot-nsys-123/gpu", nsightCommandPath("/usr/bin/nsys", "/tmp/coroot-nsys-123/gpu"))
}

func TestNsightCollectorLive(t *testing.T) {
	if os.Getenv("COROOT_TEST_NSIGHT") != "1" {
		t.Skip("set COROOT_TEST_NSIGHT=1 to run against a local Nsight Systems installation")
	}
	nsysPath, err := findNsightSystemsCLI()
	require.NoError(t, err)
	require.NoError(t, checkNsightGPUMetrics(nsysPath))

	c := &nsightCollector{nsysPath: nsysPath, interval: 3 * time.Second}
	metrics, err := c.collect()
	require.NoError(t, err)
	require.NotEmpty(t, metrics)
}
