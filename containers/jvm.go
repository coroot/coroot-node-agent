package containers

import (
	"path/filepath"
	"strconv"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/hsperf"
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

func jvmMetrics(pid uint32, c *Container) (string, []prometheus.Metric) {
	nsPid, err := proc.GetNsPid(pid)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningln(err)
		}
		return "", nil
	}
	p := proc.Path(pid, "root/tmp/hsperfdata_*/"+strconv.Itoa(int(nsPid)))
	files, _ := filepath.Glob(p)
	if len(files) != 1 {
		return "", nil
	}

	jvm, res, err := hsperf.Read(files[0])
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningln(err)
		}
		return "", nil
	}

	if *flags.EnableJavaAsyncProfiler {
		res = append(res, metrics.Gauge(metrics.JvmProfilingStatus, 1, jvm))
		if s := c.jvmProfilingStats; s != nil {
			res = append(res, metrics.Counter(metrics.JvmAllocBytes, float64(s.AllocBytes), jvm))
			res = append(res, metrics.Counter(metrics.JvmAllocObjects, float64(s.AllocObjects), jvm))
			res = append(res, metrics.Counter(metrics.JvmLockContentions, float64(s.LockContentions), jvm))
			res = append(res, metrics.Counter(metrics.JvmLockTime, float64(s.LockTimeNs)/1e9, jvm))
		}
	} else {
		res = append(res, metrics.Gauge(metrics.JvmProfilingStatus, 0, jvm))
	}

	return jvm, res
}
