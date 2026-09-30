# Coroot-node-agent

[![Go Report Card](https://goreportcard.com/badge/github.com/coroot/coroot-node-agent)](https://goreportcard.com/report/github.com/coroot/coroot-node-agent)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The agent gathers metrics related to a node and the containers running on it, and it exposes them in the Prometheus format.

It uses eBPF to track container related events such as TCP connects, so the minimum supported Linux kernel version is 4.16.
The kernel must also be built with `CONFIG_BPF_EVENTS=y` (kprobe and tracepoint BPF programs); some embedded and vendor kernels disable it.
RHEL 7 and CentOS 7 (kernel 3.10 with the eBPF backport) are supported starting from 7.6 with reduced functionality, see [RHEL 7 and CentOS 7](#rhel-7-and-centos-7).

<img src="https://coroot.com/static/img/blog/ebpf.svg" width="800" />

## Features

### TCP connection tracing

To provide visibility into the relationships between services, the agent traces containers TCP events, such as *connect()* and *listen()*.

Exported metrics are useful for:
* Obtaining an actual map of inter-service communications. It doesn't require integration of distributed tracing frameworks into your code.
* Detecting connections errors from one service to another.
* Measuring network latency between containers, nodes and availability zones.

Related blog posts:
 * [Building a service map using eBPF](https://coroot.com/blog/building-a-service-map-using-ebpf)
 * [How ping measures network round-trip time accurately using SO_TIMESTAMPING](https://coroot.com/blog/how-to-ping)
 * [The current state of eBPF portability](https://coroot.com/blog/ebpf-portability)
### Log patterns extraction

Log management is usually quite expensive. In most cases, you do not need to analyze each event individually.
It is enough to extract recurring patterns and the number of the related events.

This approach drastically reduces the amount of data required for express log analysis.

The agent discovers container logs and parses them right on the node.

At the moment the following sources are supported:
* Direct logging to files in */var/log/*
* Journald
* Dockerd (JSON file driver)
* Containerd (CRI logs)

To learn more about automated log clustering, check out the blog post "[Mining metrics from unstructured logs](https://coroot.com/blog/mining-logs-from-unstructured-logs)".

### Delay accounting

[Delay accounting](https://www.kernel.org/doc/html/latest/accounting/delay-accounting.html) allows engineers to accurately
identify situations where a container is experiencing a lack of CPU time or waiting for I/O.

The agent gathers per-process counters through [Netlink](https://man7.org/linux/man-pages/man7/netlink.7.html) and aggregates them into per-container metrics:
* [container_resources_cpu_delay_seconds_total](https://docs.coroot.com/metrics/node-agent#container_resources_cpu_delay_seconds_total)
* [container_resources_disk_delay_seconds_total](https://docs.coroot.com/metrics/node-agent#container_resources_disk_delay_seconds_total)


<img src="https://coroot.com/static/img/blog/delay_accounting_aggregation.svg" width="800" />

Related blog posts:
* [Delay accounting: an underrated feature of the Linux kernel](https://coroot.com/blog/linux-delay-accounting)


### Out-of-memory events tracing

The [container_oom_kills_total](https://docs.coroot.com/metrics/node-agent#container_oom_kills_total) metric shows that a container has been terminated by the OOM killer.

### Instance meta information

If a node is a cloud instance, the agent identifies a cloud provider and collects additional information using the related metadata services.

Supported cloud providers: [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html), [GCP](https://cloud.google.com/compute/docs/metadata/overview), [Azure](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service?tabs=linux), [Hetzner](https://docs.hetzner.cloud/#server-metadata)

Collected info:
* AccountID
* InstanceID
* Instance/machine type
* Region
* AvailabilityZone
* AvailabilityZoneId (AWS only)
* LifeCycle: on-demand/spot (AWS and GCP only)
* Private & Public IP addresses

Related blog posts:
* [Gathering cloud instance metadata in AWS, GCP and Azure](https://coroot.com/blog/cloud-metadata)

## Installation

Follow the Coroot [documentation](https://docs.coroot.com/)

### RHEL 7 and CentOS 7

The agent runs on RHEL 7.6 and later (kernel 3.10.0-957 or later, which includes the eBPF backport) with a reduced set of eBPF programs.
The following features are not available on these kernels:
* Protocol-level (L7) metrics and TLS tracing
* Network latency measurements (`container_net_latency_seconds`)
* Python GIL and Node.js event loop metrics for processes running in containers

Node and container resource metrics, TCP connections, listening sockets, retransmits, OOM kills and log parsing work as usual.

The RHEL 7 SELinux policy doesn't allow systemd services and containers to use eBPF. The denial is not logged, the agent just fails to load its programs.
The install script takes care of it for the systemd service. When running the agent as a Docker container, install the following policy module:

```bash
echo '(allow spc_t self (bpf (map_create map_read map_write prog_load prog_run)))' > coroot-node-agent-docker.cil
semodule -i coroot-node-agent-docker.cil
```

Also, replace the `/sys/kernel/tracing` volume from the documented `docker run` command with `/sys/kernel/debug:/sys/kernel/debug`. Kernel 3.10 has no `/sys/kernel/tracing`, so the mount fails.

Docker 1.13 from the CentOS repositories can't pull the agent image (it is published in the OCI format). Use Docker CE instead.

## Metrics

The collected metrics are described [here](https://docs.coroot.com/metrics/node-agent).

## Coroot

The best way to turn metrics to answers about app issues is to use [Coroot](https://github.com/coroot/coroot) - a zero-instrumentation observability tool for microservice architectures. 

A live demo of Coroot is available at [demo.coroot.com](https://demo.coroot.com)

## Contributing
To start contributing, check out our [Contributing Guide](https://github.com/coroot/coroot-node-agent/blob/main/CONTRIBUTING.md).

## License

Coroot-node-agent is licensed under the [Apache License, Version 2.0](https://github.com/coroot/coroot-node-agent/blob/main/LICENSE).

The BPF code is licensed under the General Public License, Version 2.0.
