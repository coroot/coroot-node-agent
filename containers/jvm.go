package containers

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xin053/hsperfdata"
	"k8s.io/klog/v2"
)

func jvmMetrics(pid uint32) (string, []prometheus.Metric) {
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

	pd, err := readPerfData(files[0])
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningln(err)
		}
		return "", nil
	}
	jvm := pd.getString("sun.rt.javaCommand")
	var res []prometheus.Metric

	res = append(res, gauge(metrics.JvmInfo, 1, jvm, pd.getString("java.property.java.version")))

	func() {
		size := float64(0)
		used := float64(0)
		for _, gen := range []int{0, 1} {
			spaces := pd.getInt64("sun.gc.generation.%d.spaces", gen)
			for s := 0; s < int(spaces); s++ {
				size += float64(pd.getInt64("sun.gc.generation.%d.space.%d.capacity", gen, s))
				used += float64(pd.getInt64("sun.gc.generation.%d.space.%d.used", gen, s))
			}
		}
		res = append(res, gauge(metrics.JvmHeapSize, size, jvm))
		res = append(res, gauge(metrics.JvmHeapUsed, used, jvm))
	}()

	gc := func(prefix string) {
		name := pd.getString(prefix + "name")
		if name == "" {
			return
		}
		res = append(res, counter(metrics.JvmGCTime, time.Duration(pd.getInt64(prefix+"time")).Seconds(), jvm, name))
	}
	gc("sun.gc.collector.0.")
	gc("sun.gc.collector.1.")
	gc("sun.gc.collector.2.")

	res = append(res, counter(metrics.JvmSafepointTime, time.Duration(pd.getInt64("sun.rt.safepointTime")).Seconds(), jvm))
	res = append(res, counter(metrics.JvmSafepointSyncTime, time.Duration(pd.getInt64("sun.rt.safepointSyncTime")).Seconds(), jvm))
	return jvm, res
}

type perfData struct {
	data map[string]interface{}
}

func readPerfData(p string) (*perfData, error) {
	data, err := hsperfdata.ReadPerfData(p, true)
	return &perfData{data: data}, err
}

func (pd *perfData) getString(key string) string {
	v, _ := pd.data[key].(string)
	return v
}

func (pd *perfData) getInt64(key string, a ...any) int64 {
	if len(a) > 0 {
		key = fmt.Sprintf(key, a...)
	}
	v, _ := pd.data[key].(int64)
	return v
}
