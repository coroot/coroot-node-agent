module github.com/coroot/coroot-node-agent

go 1.24.7

require (
	github.com/0xrawsec/golang-etw v1.6.2
	github.com/NVIDIA/go-nvml v0.12.4-1
	github.com/agoda-com/opentelemetry-logs-go v0.4.1
	github.com/avvmoto/buf-readerat v0.0.0-20171115124131-a17c8cb89270
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/cilium/ebpf v0.20.0
	github.com/containerd/containerd v1.7.29
	github.com/coreos/go-systemd/v22 v22.7.0
	github.com/coroot/logparser v1.4.2
	github.com/florianl/go-conntrack v0.3.0
	github.com/gobwas/glob v0.2.3
	github.com/godbus/dbus/v5 v5.2.2
	github.com/golang/snappy v0.0.4
	github.com/google/pprof v0.0.0-20260202012954-cb029daf43ef
	github.com/google/winops v0.0.0-20260218212338-878c3f651658
	github.com/grafana/jfr-parser v0.15.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/ianlancetaylor/demangle v0.0.0-20250417193237-f615e6bd150b
	github.com/jpillora/backoff v1.0.0
	github.com/klauspost/compress v1.17.11
	github.com/mdlayher/taskstats v0.0.0-20230712191918-387b3d561d14
	github.com/moby/moby/api v1.55.0
	github.com/moby/moby/client v0.5.1
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.20.5
	github.com/prometheus/client_model v0.6.1
	github.com/prometheus/common v0.61.0
	github.com/prometheus/prometheus v0.51.2
	github.com/pyroscope-io/dotnetdiag v1.2.1
	github.com/samber/lo v1.38.1
	github.com/shirou/gopsutil/v4 v4.26.5
	github.com/siderolabs/go-smbios v0.3.3
	github.com/stretchr/testify v1.11.1
	github.com/ulikunitz/xz v0.5.12
	github.com/vishvananda/netlink v1.3.1-0.20250221194427-0af32151e72b
	github.com/vishvananda/netns v0.0.5
	github.com/xin053/hsperfdata v0.2.3
	go.mongodb.org/mongo-driver v1.14.0
	go.opentelemetry.io/otel v1.35.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.28.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.28.0
	go.opentelemetry.io/otel/sdk v1.35.0
	go.opentelemetry.io/otel/trace v1.35.0
	golang.org/x/arch v0.4.0
	golang.org/x/exp v0.0.0-20240808152545-0cdaa3abc0fa
	golang.org/x/net v0.46.0
	golang.org/x/sys v0.41.0
	golang.org/x/time v0.12.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.4.0
	inet.af/netaddr v0.0.0-20230525184311-b8eac61e914a
	k8s.io/klog/v2 v2.130.1
)

require (
	cyphar.com/go-pathrs v0.2.1 // indirect
	github.com/0xrawsec/golang-utils v1.3.1 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20230306123547-8075edf89bb0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.11.7 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20231202071711-9a357b53e9c9 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/containerd/containerd/api v1.8.0 // indirect
	github.com/containerd/continuity v0.4.4 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/containerd/typeurl/v2 v2.2.0 // indirect
	github.com/cyphar/filepath-securejoin v0.6.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.7.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.10.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.2.4 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grafana/regexp v0.0.0-20221123153739-15dc172cd2db // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.20.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.1 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
	github.com/moby/sys/user v0.3.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.2.0 // indirect
	github.com/opencontainers/selinux v1.13.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	go4.org/intern v0.0.0-20211027215823-ae77deb06f29 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20230525183740-e7c30c78aeb2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/genproto v0.0.0-20240213162025-012b6fc9bca9 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250102185135-69823020774d // indirect
	google.golang.org/grpc v1.69.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/pyroscope-io/dotnetdiag => github.com/coroot/dotnetdiag v1.2.2
)
