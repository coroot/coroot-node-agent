package prom

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/golang/snappy"
	"github.com/jpillora/backoff"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/util/fmtutil"
	"k8s.io/klog/v2"
)

const RemoteWriteTimeout = 30 * time.Second

type Agent struct {
	reg    *prometheus.Registry
	url    *url.URL
	labels map[string]string

	httpClient http.Client

	spoolDir     string
	maxSpoolSize int64
}

func StartAgent(reg *prometheus.Registry, machineId string) error {
	if *flags.MetricsEndpoint == nil {
		return nil
	}
	klog.Infoln("metrics remote write endpoint:", (*flags.MetricsEndpoint).String())

	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "up"})
	up.Set(1)
	reg.MustRegister(up)

	a := &Agent{
		reg: reg,
		url: *flags.MetricsEndpoint,
		labels: map[string]string{
			model.InstanceLabel: machineId,
			model.JobLabel:      "coroot-node-agent",
		},
		httpClient: http.Client{
			Timeout: RemoteWriteTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: *flags.InsecureSkipVerify},
			},
		},
		spoolDir:     path.Join(*flags.WalDir, "spool"),
		maxSpoolSize: int64(*flags.MaxSpoolSize),
	}
	if _, err := os.Stat(*flags.WalDir); os.IsNotExist(err) {
		if err = os.Mkdir(*flags.WalDir, 0750); err != nil {
			return err
		}
	}
	if _, err := os.Stat(a.spoolDir); os.IsNotExist(err) {
		if err = os.Mkdir(a.spoolDir, 0750); err != nil {
			return err
		}
	}
	go a.sendLoop()
	go a.scrapeLoop()
	return nil
}

func (a *Agent) scrapeLoop() {
	if err := a.scrape(); err != nil {
		klog.Warningln("failed to scrape metrics:", err)
	}
	ticker := time.NewTicker(*flags.ScrapeInterval)
	for range ticker.C {
		if err := a.scrape(); err != nil {
			klog.Warningln("failed to scrape metrics:", err)
		}
	}
}

func (a *Agent) sendLoop() {
	b := backoff.Backoff{Factor: 2, Min: 5 * time.Second, Max: time.Minute}
	for {
		fName, err := a.getOldestSpoolFile()
		if err != nil || fName == "" {
			if err != nil {
				klog.Warningln("failed to get oldest spool file:", err)
			}
			time.Sleep(5 * time.Second)
			continue
		}
		err = func() error {
			if err := a.send(fName); err != nil {
				return err
			}
			return os.Remove(fName)
		}()
		if err != nil {
			dur := b.Duration()
			klog.Warningf(
				"failed to send metrics to %s, next attempt in %s: %s",
				a.url, dur.String(), err,
			)
			time.Sleep(dur)
			continue
		}
		b.Reset()
	}
}

func (a *Agent) send(fPath string) error {
	f, err := os.Open(fPath)
	if err != nil {
		return err
	}
	defer f.Close()
	req, err := http.NewRequest(http.MethodPost, a.url.String(), f)
	if err != nil {
		return err
	}
	for k, v := range common.AuthHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "coroot-node-agent")
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	t := time.Now()
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return errors.New(resp.Status)
	}
	klog.Infof("sent metrics in %s", time.Since(t).Truncate(time.Millisecond))
	return nil
}

func (a *Agent) scrape() error {
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	mfs, err := a.reg.Gather()
	if err != nil {
		return err
	}
	mfsByName := make(map[string]*dto.MetricFamily)
	for _, mf := range mfs {
		mfsByName[mf.GetName()] = mf
	}
	wr := buildWriteRequest(mfs, timestamp, a.labels)
	decompressed, err := wr.Marshal()
	if err != nil {
		return err
	}

	compressed := snappy.Encode(nil, decompressed)
	err = a.writeToSpool(timestamp, compressed)
	return err
}

func (a *Agent) writeToSpool(timestamp int64, payload []byte) error {
	if err := a.truncateSpoolIfNeeded(); err != nil {
		return err
	}
	fileName := fmt.Sprintf("spool-%d.done", timestamp)
	f, err := os.CreateTemp(a.spoolDir, fileName)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	if _, err = f.Write(payload); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path.Join(a.spoolDir, fileName)); err != nil {
		return err
	}
	return nil
}

func (a *Agent) truncateSpoolIfNeeded() error {
	files, err := a.listSpoolFiles()
	if err != nil {
		return err
	}
	if len(files) <= 1 {
		return nil
	}
	totalSize := int64(0)
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil {
			return err
		}
		totalSize += st.Size()
	}
	if totalSize > a.maxSpoolSize {
		klog.Warningln("spool size exceeded, removing the oldest file:", files[0])
		if err = os.Remove(files[0]); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) listSpoolFiles() ([]string, error) {
	entities, err := os.ReadDir(a.spoolDir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entities))
	for _, e := range entities {
		name := e.Name()
		if strings.HasPrefix(name, "spool-") && strings.HasSuffix(name, ".done") {
			files = append(files, path.Join(a.spoolDir, name))
		}
	}
	sort.Strings(files)
	return files, nil
}

func (a *Agent) getOldestSpoolFile() (string, error) {
	files, err := a.listSpoolFiles()
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", nil
	}
	return files[0], nil
}

func makeLabelsMap(m *dto.Metric, metricName string, extraLabels map[string]string) map[string]string {
	labels := make(map[string]string, len(m.Label)+len(extraLabels)+2) //1 for name, 1 for possible le
	labels[model.MetricNameLabel] = metricName
	for key, value := range extraLabels {
		labels[key] = value
	}
	for _, label := range m.Label {
		labels[label.GetName()] = label.GetValue()
	}
	return labels
}

func makeLabels(labelsMap map[string]string, metricNameSuffix, bucket string) []prompb.Label {
	l := len(labelsMap)
	if bucket != "" {
		l++
	}
	sortedLabelNames := make([]string, 0, l)
	for label := range labelsMap {
		sortedLabelNames = append(sortedLabelNames, label)
	}
	if bucket != "" {
		sortedLabelNames = append(sortedLabelNames, model.BucketLabel)
	}
	sort.Strings(sortedLabelNames)
	labels := make([]prompb.Label, len(sortedLabelNames))

	var name, value string
	var i int
	for i, name = range sortedLabelNames {
		value = labelsMap[name]
		switch name {
		case model.MetricNameLabel:
			if metricNameSuffix != "" {
				value += metricNameSuffix
			}
		case model.BucketLabel:
			value = bucket
		}
		labels[i].Name = name
		labels[i].Value = value
	}
	return labels
}

func buildWriteRequest(mfs []*dto.MetricFamily, timestamp int64, extraLabels map[string]string) *prompb.WriteRequest {
	wr := &prompb.WriteRequest{}
	for _, mf := range mfs {
		if len(mf.Metric) == 0 {
			continue
		}
		mtype := fmtutil.MetricMetadataTypeValue[mf.Type.String()]
		mName := mf.GetName()
		metadata := prompb.MetricMetadata{
			MetricFamilyName: mName,
			Type:             prompb.MetricMetadata_MetricType(mtype),
			Help:             mf.GetHelp(),
		}
		wr.Metadata = append(wr.Metadata, metadata)

		for _, metric := range mf.Metric {
			addTimeseries(wr, metric, makeLabelsMap(metric, mName, extraLabels), timestamp)
		}
	}
	return wr
}

func addTimeseries(wr *prompb.WriteRequest, m *dto.Metric, labels map[string]string, timestamp int64) {
	switch {
	case m.Gauge != nil:
		wr.Timeseries = append(wr.Timeseries, prompb.TimeSeries{
			Samples: []prompb.Sample{{
				Timestamp: timestamp,
				Value:     m.GetGauge().GetValue(),
			}},
			Labels: makeLabels(labels, "", ""),
		})
	case m.Counter != nil:
		wr.Timeseries = append(wr.Timeseries, prompb.TimeSeries{
			Samples: []prompb.Sample{{
				Timestamp: timestamp,
				Value:     m.GetCounter().GetValue(),
			}},
			Labels: makeLabels(labels, "", ""),
		})
	case m.Histogram != nil:
		for _, b := range m.GetHistogram().Bucket {
			wr.Timeseries = append(wr.Timeseries, prompb.TimeSeries{
				Samples: []prompb.Sample{{Timestamp: timestamp, Value: float64(b.GetCumulativeCount())}},
				Labels:  makeLabels(labels, "_bucket", fmt.Sprint(b.GetUpperBound())),
			})
		}
		wr.Timeseries = append(wr.Timeseries, prompb.TimeSeries{
			Samples: []prompb.Sample{{Timestamp: timestamp, Value: float64(m.Histogram.GetSampleCount())}},
			Labels:  makeLabels(labels, "_bucket", "+Inf"),
		})
		wr.Timeseries = append(wr.Timeseries, prompb.TimeSeries{
			Samples: []prompb.Sample{{Timestamp: timestamp, Value: m.GetHistogram().GetSampleSum()}},
			Labels:  makeLabels(labels, "_sum", ""),
		})
		wr.Timeseries = append(wr.Timeseries, prompb.TimeSeries{
			Samples: []prompb.Sample{{Timestamp: timestamp, Value: float64(m.GetHistogram().GetSampleCount())}},
			Labels:  makeLabels(labels, "_count", ""),
		})
	}
}
