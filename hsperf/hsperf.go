package hsperf

import (
	"fmt"
	"time"

	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xin053/hsperfdata"
)

func Read(path string) (string, []prometheus.Metric, error) {
	data, err := hsperfdata.ReadPerfData(path, true)
	if err != nil {
		return "", nil, err
	}
	pd := perfData{data: data}
	jvm := pd.getString("sun.rt.javaCommand")

	var res []prometheus.Metric
	res = append(res, prometheus.MustNewConstMetric(metrics.JvmInfo, prometheus.GaugeValue, 1, jvm, pd.getString("java.property.java.version")))

	var size, used, maxSize float64
	for _, gen := range []int{0, 1} {
		spaces := pd.getInt64("sun.gc.generation.%d.spaces", gen)
		for s := 0; s < int(spaces); s++ {
			size += float64(pd.getInt64("sun.gc.generation.%d.space.%d.capacity", gen, s))
			used += float64(pd.getInt64("sun.gc.generation.%d.space.%d.used", gen, s))
			maxSize += float64(pd.getInt64("sun.gc.generation.%d.space.%d.maxCapacity", gen, s))
		}
	}
	res = append(res, prometheus.MustNewConstMetric(metrics.JvmHeapSize, prometheus.GaugeValue, size, jvm))
	res = append(res, prometheus.MustNewConstMetric(metrics.JvmHeapUsed, prometheus.GaugeValue, used, jvm))
	if maxSize > 0 {
		res = append(res, prometheus.MustNewConstMetric(metrics.JvmHeapMaxSize, prometheus.GaugeValue, maxSize, jvm))
	}

	for _, prefix := range []string{"sun.gc.collector.0.", "sun.gc.collector.1.", "sun.gc.collector.2."} {
		name := pd.getString(prefix + "name")
		if name == "" {
			continue
		}
		res = append(res, prometheus.MustNewConstMetric(metrics.JvmGCTime, prometheus.CounterValue, time.Duration(pd.getInt64(prefix+"time")).Seconds(), jvm, name))
	}

	res = append(res, prometheus.MustNewConstMetric(metrics.JvmSafepointTime, prometheus.CounterValue, time.Duration(pd.getInt64("sun.rt.safepointTime")).Seconds(), jvm))
	res = append(res, prometheus.MustNewConstMetric(metrics.JvmSafepointSyncTime, prometheus.CounterValue, time.Duration(pd.getInt64("sun.rt.safepointSyncTime")).Seconds(), jvm))

	return jvm, res, nil
}

type perfData struct {
	data map[string]interface{}
}

func (pd perfData) getString(key string) string {
	v, _ := pd.data[key].(string)
	return v
}

func (pd perfData) getInt64(key string, a ...any) int64 {
	if len(a) > 0 {
		key = fmt.Sprintf(key, a...)
	}
	v, _ := pd.data[key].(int64)
	return v
}
