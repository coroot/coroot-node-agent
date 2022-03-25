module github.com/coroot/coroot-node-agent

go 1.16

require (
	cloud.google.com/go v0.54.0
	github.com/Microsoft/go-winio v0.4.17 // indirect
	github.com/Microsoft/hcsshim v0.8.16 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.8.1
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.5.0
	github.com/cilium/ebpf v0.6.2
	github.com/containerd/cgroups v1.0.1
	github.com/containerd/containerd v1.5.0-rc.0
	github.com/containerd/continuity v0.1.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/containerd/typeurl v1.0.2 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2
	github.com/coroot/logparser v1.0.4
	github.com/docker/docker v20.10.8+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/florianl/go-conntrack v0.3.0
	github.com/google/uuid v1.2.0 // indirect
	github.com/mdlayher/taskstats v0.0.0-20210730152605-7c2d9360c326
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/runc v1.0.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/prometheus/client_golang v1.11.0
	github.com/stretchr/testify v1.7.0
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f
	golang.org/x/mod v0.3.0
	golang.org/x/net v0.0.0-20210913180222-943fd674d43e
	golang.org/x/sys v0.0.0-20210915083310-ed5796bab164
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	inet.af/netaddr v0.0.0-20210903134321-85fa6c94624e
	k8s.io/klog/v2 v2.20.0
)
