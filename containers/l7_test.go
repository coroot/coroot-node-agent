package containers

import (
	"math"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"inet.af/netaddr"
)

func destKey(host string, port uint16) common.DestinationKey {
	ip := netaddr.MustParseIP(host)
	if ip.IsZero() {
		ip = netaddr.IPv4(10, 0, 0, 1)
	}
	dst := netaddr.IPPortFrom(ip, port)
	return common.NewDestinationKey(dst, dst, nil)
}

func TestLightweightHistogramObserve(t *testing.T) {
	h := newLightweightHistogram()

	h.observe(0.003)
	h.observe(0.05)
	h.observe(0.05)
	h.observe(7)
	h.observe(15)

	if h.count != 5 {
		t.Fatalf("count: got %d, want 5", h.count)
	}

	wantSum := 0.003 + 0.05 + 0.05 + 7.0 + 15.0
	if math.Abs(h.sum-wantSum) > 1e-9 {
		t.Fatalf("sum: got %f, want %f", h.sum, wantSum)
	}

	bucketTests := []struct {
		bucket float64
		want   uint64
	}{
		{0.005, 1},
		{0.01, 1},
		{0.025, 1},
		{0.05, 3},
		{0.1, 3},
		{0.25, 3},
		{0.5, 3},
		{1, 3},
		{2.5, 3},
		{5, 3},
		{10, 4},
	}
	for i, bt := range bucketTests {
		if h.bucketCounts[i] != bt.want {
			t.Errorf("bucket[%d] (%g): got %d, want %d", i, bt.bucket, h.bucketCounts[i], bt.want)
		}
	}
}

func TestLightweightHistogramZeroValue(t *testing.T) {
	h := newLightweightHistogram()
	h.observe(0)

	if h.count != 1 {
		t.Fatalf("count: got %d, want 1", h.count)
	}
	for i := range h.bucketCounts {
		if h.bucketCounts[i] != 1 {
			t.Errorf("bucket[%d]: got %d, want 1 (0 <= all buckets)", i, h.bucketCounts[i])
		}
	}
}

func TestLightweightHistogramExactBoundary(t *testing.T) {
	h := newLightweightHistogram()

	for _, b := range defaultBuckets {
		h.observe(b)
	}

	if h.count != uint64(len(defaultBuckets)) {
		t.Fatalf("count: got %d, want %d", h.count, len(defaultBuckets))
	}

	for i := range defaultBuckets {
		if h.bucketCounts[i] != uint64(i+1) {
			t.Errorf("bucket[%d] (%g): got %d, want %d", i, defaultBuckets[i], h.bucketCounts[i], i+1)
		}
	}
}

func TestL7MetricsObserveNewStatus(t *testing.T) {
	m := &L7Metrics{latency: newLightweightHistogram()}

	m.observe("200", "", 100*time.Millisecond)
	m.observe("500", "", 200*time.Millisecond)
	m.observe("200", "", 50*time.Millisecond)

	if len(m.requests) != 2 {
		t.Fatalf("requests: got %d, want 2", len(m.requests))
	}

	var found200, found500 bool
	for _, r := range m.requests {
		switch r.status {
		case "200":
			found200 = true
			if r.count != 2 {
				t.Errorf("status 200 count: got %d, want 2", r.count)
			}
		case "500":
			found500 = true
			if r.count != 1 {
				t.Errorf("status 500 count: got %d, want 1", r.count)
			}
		}
	}
	if !found200 || !found500 {
		t.Fatal("missing expected status entries")
	}

	if m.latency.count != 3 {
		t.Errorf("latency count: got %d, want 3", m.latency.count)
	}
}

func TestL7MetricsObserveWithMethod(t *testing.T) {
	m := &L7Metrics{latency: newLightweightHistogram()}

	m.observe("200", "GET", 0)
	m.observe("200", "POST", 0)
	m.observe("200", "GET", 0)

	if len(m.requests) != 2 {
		t.Fatalf("requests: got %d, want 2", len(m.requests))
	}
	for _, r := range m.requests {
		if r.method == "GET" && r.count != 2 {
			t.Errorf("GET count: got %d, want 2", r.count)
		}
		if r.method == "POST" && r.count != 1 {
			t.Errorf("POST count: got %d, want 1", r.count)
		}
	}
}

func TestL7MetricsObserveZeroDuration(t *testing.T) {
	m := &L7Metrics{latency: newLightweightHistogram()}

	m.observe("200", "", 0)

	if m.latency.count != 0 {
		t.Errorf("latency should not be recorded for zero duration: got %d", m.latency.count)
	}
}

func TestL7MetricsObserveNoLatencyField(t *testing.T) {
	m := &L7Metrics{}

	m.observe("200", "", 100*time.Millisecond)

	if len(m.requests) != 1 {
		t.Fatalf("requests: got %d, want 1", len(m.requests))
	}
	if m.requests[0].count != 1 {
		t.Errorf("request count: got %d, want 1", m.requests[0].count)
	}
}

func TestL7StatsGetHTTP2Normalization(t *testing.T) {
	s := L7Stats{}
	key := destKey("10.0.0.1", 80)

	m1 := s.get(l7.ProtocolHTTP2, key)
	m2 := s.get(l7.ProtocolHTTP, key)

	if m1 != m2 {
		t.Fatal("HTTP2 and HTTP should resolve to same L7Metrics")
	}

	if _, ok := s[l7.ProtocolHTTP2]; ok {
		t.Fatal("should not store ProtocolHTTP2 key")
	}
	if _, ok := s[l7.ProtocolHTTP]; !ok {
		t.Fatal("should store ProtocolHTTP key")
	}
}

func TestL7StatsGetNoLatencyForMessaging(t *testing.T) {
	s := L7Stats{}
	key := destKey("10.0.0.1", 5672)

	mRabbit := s.get(l7.ProtocolRabbitmq, key)
	if mRabbit.latency != nil {
		t.Fatal("Rabbitmq should not have latency histogram")
	}

	mNats := s.get(l7.ProtocolNats, key)
	if mNats.latency != nil {
		t.Fatal("Nats should not have latency histogram")
	}
}

func TestL7StatsGetCreatesLatencyForOthers(t *testing.T) {
	key := destKey("10.0.0.1", 5432)

	protos := []l7.Protocol{
		l7.ProtocolHTTP,
		l7.ProtocolPostgres,
		l7.ProtocolRedis,
		l7.ProtocolMemcached,
		l7.ProtocolMysql,
		l7.ProtocolMongo,
		l7.ProtocolKafka,
		l7.ProtocolCassandra,
		l7.ProtocolDubbo2,
		l7.ProtocolClickhouse,
		l7.ProtocolZookeeper,
		l7.ProtocolFoundationDB,
	}
	for _, p := range protos {
		s2 := L7Stats{}
		m := s2.get(p, key)
		if m.latency == nil {
			t.Errorf("protocol %v should have latency histogram", p)
		}
	}
}

func TestL7StatsGetSameEntry(t *testing.T) {
	s := L7Stats{}
	key := destKey("10.0.0.1", 6379)

	m1 := s.get(l7.ProtocolRedis, key)
	m2 := s.get(l7.ProtocolRedis, key)

	if m1 != m2 {
		t.Fatal("same protocol+key should return same L7Metrics")
	}
}

func TestL7StatsDelete(t *testing.T) {
	s := L7Stats{}
	key1 := destKey("10.0.0.1", 80)
	key2 := destKey("10.0.0.2", 80)

	s.get(l7.ProtocolHTTP, key1)
	s.get(l7.ProtocolHTTP, key2)

	if len(s[l7.ProtocolHTTP]) != 2 {
		t.Fatalf("proto map: got %d, want 2", len(s[l7.ProtocolHTTP]))
	}

	s.delete(key1.Destination())

	if len(s[l7.ProtocolHTTP]) != 1 {
		t.Fatalf("after delete: got %d, want 1", len(s[l7.ProtocolHTTP]))
	}
	if _, ok := s[l7.ProtocolHTTP][key2]; !ok {
		t.Fatal("key2 should still exist")
	}
}

func TestL7StatsCollect(t *testing.T) {
	s := L7Stats{}
	key := destKey("10.0.0.1", 443)

	m := s.get(l7.ProtocolHTTP, key)
	m.observe("200", "", 100*time.Millisecond)
	m.observe("200", "", 200*time.Millisecond)
	m.observe("500", "", 50*time.Millisecond)

	reg := prometheus.NewRegistry()
	reg.MustRegister(&collectorShim{s: s})

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	reqMF := findMetricFamily(mfs, "container_http_requests_total")
	if reqMF == nil {
		t.Fatal("container_http_requests_total not found")
	}
	if len(reqMF.Metric) != 2 {
		t.Fatalf("request metrics: got %d, want 2 (status 200 and 500)", len(reqMF.Metric))
	}

	latMF := findMetricFamily(mfs, "container_http_requests_duration_seconds_total_bucket")
	if latMF == nil {
		t.Fatal("container_http_requests_duration_seconds_total_bucket not found")
	}
	if findMetricFamily(mfs, "container_http_requests_duration_seconds_total_sum") == nil {
		t.Fatal("container_http_requests_duration_seconds_total_sum not found")
	}
	if findMetricFamily(mfs, "container_http_requests_duration_seconds_total_count") == nil {
		t.Fatal("container_http_requests_duration_seconds_total_count not found")
	}
}

func TestL7StatsCollectWithMethod(t *testing.T) {
	s := L7Stats{}
	key := destKey("10.0.0.1", 443)

	m := s.get(l7.ProtocolHTTP, key)
	m.observe("200", "GET", 0)
	m.observe("200", "POST", 0)

	reg := prometheus.NewRegistry()
	reg.MustRegister(&collectorShim{s: s})

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	reqMF := findMetricFamily(mfs, "container_http_requests_total")
	if reqMF == nil {
		t.Fatal("container_http_requests_total not found")
	}

	methods := map[string]bool{}
	for _, m := range reqMF.Metric {
		for _, l := range m.Label {
			if l.GetName() == "method" {
				methods[l.GetValue()] = true
			}
		}
	}
	if !methods["GET"] || !methods["POST"] {
		t.Fatalf("expected GET and POST methods, got %v", methods)
	}
}

func TestL7StatsCollectMultipleProtocols(t *testing.T) {
	s := L7Stats{}
	key := destKey("10.0.0.1", 5432)

	mPg := s.get(l7.ProtocolPostgres, key)
	mPg.observe("ok", "", 10*time.Millisecond)

	mRedis := s.get(l7.ProtocolRedis, key)
	mRedis.observe("ok", "", 5*time.Millisecond)

	reg := prometheus.NewRegistry()
	reg.MustRegister(&collectorShim{s: s})

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	if findMetricFamily(mfs, "container_postgres_queries_total") == nil {
		t.Fatal("container_postgres_queries_total not found")
	}
	if findMetricFamily(mfs, "container_redis_queries_total") == nil {
		t.Fatal("container_redis_queries_total not found")
	}
}

func TestDnsStatsObserve(t *testing.T) {
	d := &DnsStats{}

	d.observe("TypeA", "example.com", "NOERROR")
	d.observe("TypeA", "example.com", "NOERROR")
	d.observe("TypeAAAA", "example.com", "NOERROR")
	d.observe("TypeA", "other.com", "NXDOMAIN")

	if len(d.requests) != 3 {
		t.Fatalf("unique entries: got %d, want 3", len(d.requests))
	}

	var found bool
	for _, r := range d.requests {
		if r.requestType == "TypeA" && r.domain == "example.com" && r.status == "NOERROR" {
			if r.count != 2 {
				t.Errorf("example.com/TypeA count: got %d, want 2", r.count)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing TypeA/example.com/NOERROR entry")
	}
}

func TestDnsStatsObserveLatency(t *testing.T) {
	d := &DnsStats{}

	if d.latency != nil {
		t.Fatal("latency should start nil")
	}

	d.observeLatency(0.005)
	if d.latency == nil {
		t.Fatal("latency should be created on first observe")
	}
	if d.latency.count != 1 {
		t.Errorf("latency count: got %d, want 1", d.latency.count)
	}

	d.observeLatency(0.01)
	if d.latency.count != 2 {
		t.Errorf("latency count: got %d, want 2", d.latency.count)
	}
}

func TestDnsStatsCollect(t *testing.T) {
	d := &DnsStats{}
	d.observe("TypeA", "example.com", "NOERROR")
	d.observe("TypeA", "example.com", "NOERROR")
	d.observe("TypeAAAA", "example.com", "NOERROR")
	d.observeLatency(0.01)
	d.observeLatency(0.05)

	reg := prometheus.NewRegistry()
	reg.MustRegister(&dnsCollectorShim{d: d})

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	reqMF := findMetricFamily(mfs, "container_dns_requests_total")
	if reqMF == nil {
		t.Fatal("container_dns_requests_total not found")
	}
	if len(reqMF.Metric) != 2 {
		t.Fatalf("dns request metrics: got %d, want 2", len(reqMF.Metric))
	}

	latMF := findMetricFamily(mfs, "container_dns_requests_duration_seconds_total_bucket")
	if latMF == nil {
		t.Fatal("container_dns_requests_duration_seconds_total_bucket not found")
	}
}

func TestEmitHistogramCumulative(t *testing.T) {
	descs := l7Descs[l7.ProtocolHTTP]
	h := newLightweightHistogram()
	h.observe(0.003)
	h.observe(0.05)
	h.observe(0.05)
	h.observe(7)
	h.observe(15)

	ch := make(chan prometheus.Metric, 100)
	emitHistogram(ch, descs, "dest", "act", h)
	close(ch)

	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}

	if len(metrics) != 14 {
		t.Fatalf("histogram metrics: got %d, want 14", len(metrics))
	}

	pb := &dto.Metric{}
	if err := metrics[11].Write(pb); err != nil {
		t.Fatal(err)
	}
	if pb.GetCounter().GetValue() != 5 {
		t.Errorf("+Inf: got %f, want 5 (h.count)", pb.GetCounter().GetValue())
	}

	bucketValues := []float64{1, 1, 1, 3, 3, 3, 3, 3, 3, 3, 4}
	for i, want := range bucketValues {
		pb := &dto.Metric{}
		if err := metrics[i].Write(pb); err != nil {
			t.Fatal(err)
		}
		if pb.GetCounter().GetValue() != want {
			t.Errorf("bucket[%d] (%g): got %f, want %f", i, defaultBuckets[i], pb.GetCounter().GetValue(), want)
		}
	}

	sumM := metrics[12]
	pb2 := &dto.Metric{}
	if err := sumM.Write(pb2); err != nil {
		t.Fatal(err)
	}
	wantSum := 0.003 + 0.05 + 0.05 + 7.0 + 15.0
	if math.Abs(pb2.GetCounter().GetValue()-wantSum) > 1e-9 {
		t.Errorf("sum: got %f, want %f", pb2.GetCounter().GetValue(), wantSum)
	}

	countM := metrics[13]
	pb3 := &dto.Metric{}
	if err := countM.Write(pb3); err != nil {
		t.Fatal(err)
	}
	if pb3.GetCounter().GetValue() != 5 {
		t.Errorf("count: got %f, want 5", pb3.GetCounter().GetValue())
	}
}

func TestSortFloatStr(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{0.005, "0.005"},
		{0.01, "0.01"},
		{0.025, "0.025"},
		{0.05, "0.05"},
		{0.1, "0.1"},
		{0.25, "0.25"},
		{0.5, "0.5"},
		{1, "1"},
		{2.5, "2.5"},
		{5, "5"},
		{10, "10"},
	}
	for _, tt := range tests {
		got := sortFloatStr(tt.input)
		if got != tt.want {
			t.Errorf("sortFloatStr(%g): got %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestL7StatsCollectEmpty(t *testing.T) {
	s := L7Stats{}

	ch := make(chan prometheus.Metric, 10)
	s.collect(ch)
	close(ch)

	var count int
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("empty L7Stats should emit 0 metrics, got %d", count)
	}
}

func TestDnsStatsCollectNoLatency(t *testing.T) {
	d := &DnsStats{}
	d.observe("TypeA", "example.com", "NOERROR")

	reg := prometheus.NewRegistry()
	reg.MustRegister(&dnsCollectorShim{d: d})

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	latMF := findMetricFamily(mfs, "container_dns_requests_duration_seconds_total")
	if latMF != nil {
		t.Error("should not emit latency metrics when no latency observed")
	}
}

func TestEmitHistogramDNSCumulative(t *testing.T) {
	h := newLightweightHistogram()
	h.observe(0.001)
	h.observe(0.001)

	ch := make(chan prometheus.Metric, 100)
	emitHistogramDNS(ch, h)
	close(ch)

	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}

	if len(metrics) != 14 {
		t.Fatalf("dns histogram metrics: got %d, want 14", len(metrics))
	}

	pb := &dto.Metric{}
	if err := metrics[0].Write(pb); err != nil {
		t.Fatal(err)
	}
	if pb.GetCounter().GetValue() != 2 {
		t.Errorf("first bucket (0.005): got %f, want 2", pb.GetCounter().GetValue())
	}
}

func TestDestinationKeyLabelValues(t *testing.T) {
	dst := netaddr.MustParseIP("10.0.0.1")
	key := common.NewDestinationKey(
		netaddr.IPPortFrom(dst, 80),
		netaddr.IPPortFrom(dst, 80),
		nil,
	)
	if key.DestinationLabelValue() != "10.0.0.1:80" {
		t.Errorf("DestinationLabelValue: got %q", key.DestinationLabelValue())
	}
	if key.ActualDestinationLabelValue() != "10.0.0.1:80" {
		t.Errorf("ActualDestinationLabelValue: got %q", key.ActualDestinationLabelValue())
	}
}

func TestDefaultBucketsLen(t *testing.T) {
	if len(defaultBuckets) != 11 {
		t.Fatalf("defaultBuckets: got %d, want 11", len(defaultBuckets))
	}
}

func TestL7DescCacheInit(t *testing.T) {
	for proto := range L7Requests {
		descs, ok := l7Descs[proto]
		if !ok {
			t.Errorf("l7Descs missing for protocol %v", proto)
			continue
		}
		if descs.requests == nil {
			t.Errorf("requests desc nil for protocol %v", proto)
		}
		if descs.requestsWithMethod == nil {
			t.Errorf("requestsWithMethod desc nil for protocol %v", proto)
		}
		if _, hasLat := L7Latency[proto]; hasLat {
			if descs.latency == nil {
				t.Errorf("latency desc nil for protocol %v", proto)
			}
			if descs.latencySum == nil {
				t.Errorf("latencySum desc nil for protocol %v", proto)
			}
			if descs.latencyCount == nil {
				t.Errorf("latencyCount desc nil for protocol %v", proto)
			}
		}
	}
}

func TestDnsDescsInit(t *testing.T) {
	if dnsDescs.requests == nil {
		t.Fatal("dnsDescs.requests should be initialized")
	}
	if dnsDescs.latency == nil {
		t.Fatal("dnsDescs.latency should be initialized")
	}
	if dnsDescs.latencySum == nil {
		t.Fatal("dnsDescs.latencySum should be initialized")
	}
	if dnsDescs.latencyCount == nil {
		t.Fatal("dnsDescs.latencyCount should be initialized")
	}
}

type collectorShim struct {
	s L7Stats
}

func (c *collectorShim) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("l7_shim", "", nil, nil)
}

func (c *collectorShim) Collect(ch chan<- prometheus.Metric) {
	c.s.collect(ch)
}

type dnsCollectorShim struct {
	d *DnsStats
}

func (c *dnsCollectorShim) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("dns_shim", "", nil, nil)
}

func (c *dnsCollectorShim) Collect(ch chan<- prometheus.Metric) {
	c.d.collect(ch)
}

func findMetricFamily(mfs []*dto.MetricFamily, name string) *dto.MetricFamily {
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}
