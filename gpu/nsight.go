package gpu

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

const (
	nsightCaptureDuration = 2 * time.Second
	nsightMetricsFreqHz   = 100
	nsightHostRoot        = "/proc/1/root"

	nsightMetricGPUUtilization   = "GR Active [Throughput %]"
	nsightMetricDRAMRead         = "DRAM Read Bandwidth [Throughput %]"
	nsightMetricDRAMWrite        = "DRAM Write Bandwidth [Throughput %]"
	nsightMetricComputeOccupancy = "Compute Warps in Flight [Throughput %]"
)

var nsightMetricsQuery = fmt.Sprintf(`
WITH metric_samples AS (
    SELECT
        g.uuid AS gpu_uuid,
        gm.timestamp AS timestamp,
        max(CASE WHEN tim.metricName = %[1]q THEN gm.value END) AS gpu_utilization,
        min(100, coalesce(max(CASE WHEN tim.metricName = %[2]q THEN gm.value END), 0) +
                 coalesce(max(CASE WHEN tim.metricName = %[3]q THEN gm.value END), 0)) AS memory_utilization,
        max(CASE WHEN tim.metricName = %[4]q THEN gm.value END) AS compute_occupancy
    FROM GPU_METRICS gm
    JOIN TARGET_INFO_GPU_METRICS tim ON gm.typeId = tim.typeId AND gm.metricId = tim.metricId
    JOIN TARGET_INFO_GPU g ON tim.sourceId = g.vmId + ((g.id + 1) * 4294967296)
    WHERE tim.metricName IN (%[1]q, %[2]q, %[3]q, %[4]q)
    GROUP BY g.uuid, gm.timestamp
)
SELECT
    gpu_uuid,
    avg(gpu_utilization) AS gpu_utilization_avg,
    max(gpu_utilization) AS gpu_utilization_peak,
    avg(memory_utilization) AS memory_utilization_avg,
    max(memory_utilization) AS memory_utilization_peak,
    avg(compute_occupancy) AS compute_occupancy_avg,
    max(compute_occupancy) AS compute_occupancy_peak
FROM metric_samples
GROUP BY gpu_uuid
ORDER BY gpu_uuid;
`, nsightMetricGPUUtilization, nsightMetricDRAMRead, nsightMetricDRAMWrite, nsightMetricComputeOccupancy)

var nsightStatsReport = fmt.Sprintf(`#!/usr/bin/env python
import nsysstats

class CorootGpuMetrics(nsysstats.StatsReport):
    display_name = 'Coroot GPU Metrics'
    query = r"""%s"""
    table_checks = {
        'GPU_METRICS': '{DBFILE} does not contain GPU_METRICS table.',
        'TARGET_INFO_GPU': '{DBFILE} does not contain TARGET_INFO_GPU table.',
        'TARGET_INFO_GPU_METRICS': '{DBFILE} does not contain TARGET_INFO_GPU_METRICS table.',
    }

if __name__ == "__main__":
    CorootGpuMetrics.Main()
`, nsightMetricsQuery)

type nsightCollector struct {
	nsysPath string
	interval time.Duration

	lock    sync.RWMutex
	metrics map[string]nsightMetrics

	stopCh chan struct{}

	lastErr   string
	lastErrAt time.Time
}

type nsightMetrics struct {
	GPUUtilizationAvg     float64
	GPUUtilizationPeak    float64
	MemoryUtilizationAvg  float64
	MemoryUtilizationPeak float64
	ComputeOccupancyAvg   float64
	ComputeOccupancyPeak  float64
	CollectedAt           time.Time
}

func newNsightCollector(devices []*Device) (*nsightCollector, error) {
	if len(devices) == 0 {
		return nil, errors.New("no NVIDIA GPUs detected")
	}
	var errs []string
	var nsysPath string
	for _, candidate := range findNsightSystemsCLIs() {
		if err := checkNsightGPUMetrics(candidate); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", candidate, err))
			continue
		}
		nsysPath = candidate
		break
	}
	if nsysPath == "" {
		if len(errs) == 0 {
			return nil, errors.New("nsys not found")
		}
		return nil, fmt.Errorf("no usable nsys GPU metrics collector found: %s", strings.Join(errs, "; "))
	}

	interval := *flags.ScrapeInterval
	if interval < nsightCaptureDuration+time.Second {
		interval = nsightCaptureDuration + time.Second
	}
	klog.Infof("Nsight Systems GPU metrics enabled: %s", nsysPath)
	return &nsightCollector{
		nsysPath: nsysPath,
		interval: interval,
		metrics:  map[string]nsightMetrics{},
		stopCh:   make(chan struct{}),
	}, nil
}

func (c *nsightCollector) Start() {
	go func() {
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-timer.C:
				if metrics, err := c.collect(); err != nil {
					c.logError(err)
				} else {
					c.lock.Lock()
					c.metrics = metrics
					c.lock.Unlock()
				}
				timer.Reset(c.interval)
			}
		}
	}()
}

func (c *nsightCollector) Close() {
	close(c.stopCh)
}

func (c *nsightCollector) Snapshot() map[string]nsightMetrics {
	if c == nil {
		return nil
	}
	maxAge := c.interval * 3
	now := time.Now()
	res := map[string]nsightMetrics{}
	c.lock.RLock()
	defer c.lock.RUnlock()
	for uuid, m := range c.metrics {
		if now.Sub(m.CollectedAt) <= maxAge {
			res[uuid] = m
		}
	}
	return res
}

func (c *nsightCollector) collect() (map[string]nsightMetrics, error) {
	tmpRoot := ""
	if nsightRunsOnHost(c.nsysPath) {
		tmpRoot = proc.HostPath("/tmp")
	}
	dir, err := os.MkdirTemp(tmpRoot, "coroot-nsys-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	reportBase := filepath.Join(dir, "gpu")
	reportPath := reportBase + ".nsys-rep"
	reportPluginPath := filepath.Join(dir, "coroot_gpu_metrics.py")
	if err = os.WriteFile(reportPluginPath, []byte(nsightStatsReport), 0600); err != nil {
		return nil, err
	}
	commandDir := nsightCommandPath(c.nsysPath, dir)
	commandReportBase := filepath.Join(commandDir, "gpu")
	commandReportPath := commandReportBase + ".nsys-rep"
	commandSqlitePath := commandReportBase + ".sqlite"

	ctx, cancel := context.WithTimeout(context.Background(), nsightCaptureDuration+30*time.Second)
	defer cancel()
	profileArgs := []string{
		"profile",
		fmt.Sprintf("--duration=%d", int(nsightCaptureDuration.Seconds())),
		"--sample=none",
		"--cpuctxsw=none",
		"--trace=none",
		"--gpu-metrics-devices=all",
		fmt.Sprintf("--gpu-metrics-frequency=%d", nsightMetricsFreqHz),
		"--stats=false",
		"--show-output=false",
		"--force-overwrite=true",
		"--output=" + commandReportBase,
		"/bin/sleep",
		strconv.Itoa(int(nsightCaptureDuration.Seconds())),
	}
	if out, err := commandOutput(ctx, c.nsysPath, profileArgs...); err != nil {
		return nil, fmt.Errorf("nsys profile failed: %w: %s", err, summarizeCommandOutput(out))
	}
	if _, err = os.Stat(reportPath); err != nil {
		return nil, fmt.Errorf("nsys profile did not create %s: %w", reportPath, err)
	}

	statsArgs := []string{
		"stats",
		"--quiet",
		"--force-export=true",
		"--sqlite=" + commandSqlitePath,
		"--report-dir",
		commandDir,
		"--report",
		"coroot_gpu_metrics",
		"--format",
		"csv",
		"--output",
		"-",
		commandReportPath,
	}
	out, err := commandOutput(ctx, c.nsysPath, statsArgs...)
	if err != nil {
		return nil, fmt.Errorf("nsys stats failed: %w: %s", err, summarizeCommandOutput(out))
	}
	metrics, err := parseNsightMetricsCSV(out, time.Now())
	if err != nil {
		return nil, err
	}
	if len(metrics) == 0 {
		return nil, errors.New("nsys stats returned no GPU metrics")
	}
	return metrics, nil
}

func (c *nsightCollector) logError(err error) {
	msg := err.Error()
	now := time.Now()
	if msg == c.lastErr && now.Sub(c.lastErrAt) < time.Minute {
		return
	}
	c.lastErr = msg
	c.lastErrAt = now
	klog.Warningf("failed to collect Nsight Systems GPU metrics: %s", msg)
}

func findNsightSystemsCLI() (string, error) {
	candidates := findNsightSystemsCLIs()
	if len(candidates) == 0 {
		return "", errors.New("nsys not found")
	}
	return candidates[0], nil
}

func findNsightSystemsCLIs() []string {
	var candidates []string
	seen := map[string]struct{}{}
	add := func(path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0111 != 0 {
			seen[path] = struct{}{}
			candidates = append(candidates, path)
		}
	}
	if path, err := exec.LookPath("nsys"); err == nil {
		add(path)
	}
	for _, p := range []string{
		"/opt/nvidia/nsight-systems/*/target-linux-x64/nsys",
		"/opt/nvidia/nsight-systems/*/target-linux-sbsa-armv8/nsys",
		"/opt/nvidia/nsight-systems/*/target-linux-ppc64le/nsys",
		"/opt/nvidia/nsight-systems-cli/*/target-linux-x64/nsys",
		"/opt/nvidia/nsight-systems-cli/*/target-linux-sbsa-armv8/nsys",
		"/opt/nvidia/nsight-systems-cli/*/target-linux-ppc64le/nsys",
	} {
		if !nsightPathMatchesArch(p) {
			continue
		}
		matches, _ := filepath.Glob(proc.HostPath(p))
		for _, match := range matches {
			add(match)
		}
	}
	return candidates
}

func nsightPathMatchesArch(path string) bool {
	switch runtime.GOARCH {
	case "amd64":
		return strings.Contains(path, "x64")
	case "arm64":
		return strings.Contains(path, "sbsa-armv8")
	case "ppc64le":
		return strings.Contains(path, "ppc64le")
	default:
		return false
	}
}

func checkNsightGPUMetrics(nsysPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := commandOutput(ctx, nsysPath, "profile", "--gpu-metrics-devices=help", "true")
	if err != nil {
		return fmt.Errorf("unable to query nsys GPU metrics support: %w: %s", err, summarizeCommandOutput(out))
	}
	if !bytes.Contains(out, []byte("\n\tall:")) && !bytes.Contains(out, []byte("\n    all:")) {
		return fmt.Errorf("no supported GPU metrics devices reported by nsys: %s", summarizeCommandOutput(out))
	}
	return nil
}

func commandOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	if nsightRunsOnHost(name) {
		name = nsightCommandPath(name, name)
		args = append([]string{nsightHostRoot, name}, args...)
		name = "chroot"
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "TERM=dumb", "NO_COLOR=1")
	return cmd.CombinedOutput()
}

func nsightRunsOnHost(path string) bool {
	return strings.HasPrefix(filepath.Clean(path), nsightHostRoot+string(os.PathSeparator))
}

func nsightCommandPath(nsysPath, path string) string {
	if !nsightRunsOnHost(nsysPath) {
		return path
	}
	clean := filepath.Clean(path)
	if clean == nsightHostRoot {
		return "/"
	}
	if strings.HasPrefix(clean, nsightHostRoot+string(os.PathSeparator)) {
		return strings.TrimPrefix(clean, nsightHostRoot)
	}
	return path
}

func summarizeCommandOutput(out []byte) string {
	const max = 512
	s := strings.TrimSpace(strings.ReplaceAll(string(out), "\r", "\n"))
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func parseNsightMetricsCSV(payload []byte, collectedAt time.Time) (map[string]nsightMetrics, error) {
	reader := csv.NewReader(bytes.NewReader(payload))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("invalid nsys stats CSV: %w", err)
	}
	res := map[string]nsightMetrics{}
	for _, row := range records {
		if len(row) == 0 || row[0] == "gpu_uuid" {
			continue
		}
		if len(row) < 7 {
			return nil, fmt.Errorf("invalid nsys stats row: %q", row)
		}
		uuid := normalizeGPUUUID(row[0])
		if uuid == "" {
			continue
		}
		m := nsightMetrics{CollectedAt: collectedAt}
		if m.GPUUtilizationAvg, err = parseOptionalFloat(row[1]); err != nil {
			return nil, err
		}
		if m.GPUUtilizationPeak, err = parseOptionalFloat(row[2]); err != nil {
			return nil, err
		}
		if m.MemoryUtilizationAvg, err = parseOptionalFloat(row[3]); err != nil {
			return nil, err
		}
		if m.MemoryUtilizationPeak, err = parseOptionalFloat(row[4]); err != nil {
			return nil, err
		}
		if m.ComputeOccupancyAvg, err = parseOptionalFloat(row[5]); err != nil {
			return nil, err
		}
		if m.ComputeOccupancyPeak, err = parseOptionalFloat(row[6]); err != nil {
			return nil, err
		}
		res[uuid] = m
	}
	return res, nil
}

func parseOptionalFloat(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid nsys metric value %q: %w", s, err)
	}
	return v, nil
}

func normalizeGPUUUID(uuid string) string {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" || strings.HasPrefix(uuid, "GPU-") {
		return uuid
	}
	return "GPU-" + uuid
}
