# Coroot-node-agent

[![Go Report Card](https://goreportcard.com/badge/github.com/coroot/coroot-node-agent)](https://goreportcard.com/report/github.com/coroot/coroot-node-agent)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The agent gathers metrics related to a node and the containers running on it, and it exposes them in the Prometheus format.

It uses eBPF to track container related events such as TCP connects, so the minimum supported Linux kernel version is 4.16.

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
* [container_resources_cpu_delay_seconds_total](https://coroot.com/docs/metrics/node-agent#container_resources_cpu_delay_seconds_total)
* [container_resources_disk_delay_seconds_total](https://coroot.com/docs/metrics/node-agent#container_resources_disk_delay_seconds_total)


<img src="https://coroot.com/static/img/blog/delay_accounting_aggregation.svg" width="800" />

Related blog posts:
* [Delay accounting: an underrated feature of the Linux kernel](https://coroot.com/blog/linux-delay-accounting)


### Out-of-memory events tracing

The [container_oom_kills_total](https://coroot.com/docs/metrics/node-agent#container_oom_kills_total) metric shows that a container has been terminated by the OOM killer.

### Instance meta information

If a node is a cloud instance, the agent identifies a cloud provider and collects additional information using the related metadata services.

Supported cloud providers: [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html), [GCP](https://cloud.google.com/compute/docs/metadata/overview), [Azure](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service?tabs=linux)

Collected info:
* AccountID
* InstanceID
* Instance/machine type
* Region
* AvailabilityZone + AvailabilityZoneId (AWS only)
* LifeCycle: on-demand/spot (AWS and GCP only)
* Private & Public IP addresses

Related blog posts:
* [Gathering cloud instance metadata in AWS, GCP and Azure](https://coroot.com/blog/cloud-metadata)

## Run

### Requirements

The agent requires some privileges for getting access to container data, such as logs, performance counters and TCP sockets:
* privileged mode (`securityContext.privileged: true`)
* the host process ID namespace (`hostPID: true`)
* `/sys/fs/cgroup` and `/sys/kernel/debug` should be mounted to the agent's container

### Kubernetes

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: coroot

---

apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    app: coroot-node-agent
  name: coroot-node-agent
  namespace: coroot
spec:
  selector:
    matchLabels:
      app: coroot-node-agent
  template:
    metadata:
      labels:
        app: coroot-node-agent
      annotations:
        prometheus.io/scrape: 'true'
        prometheus.io/port: '80'
    spec:
      tolerations:
        - operator: Exists
      hostPID: true
      containers:
        - name: coroot-node-agent
          image: ghcr.io/coroot/coroot-node-agent:latest
          args: ["--cgroupfs-root", "/host/sys/fs/cgroup"]
          ports:
            - containerPort: 80
              name: http
          securityContext:
            privileged: true
          volumeMounts:
            - mountPath: /host/sys/fs/cgroup
              name: cgroupfs
              readOnly: true
            - mountPath: /sys/kernel/debug
              name: debugfs
              readOnly: false
      volumes:
        - hostPath:
            path: /sys/fs/cgroup
          name: cgroupfs
        - hostPath:
            path: /sys/kernel/debug
          name: debugfs
```

If you use [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator), 
you will also need to create a PodMonitor:
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: coroot-node-agent
  namespace: coroot
spec:
  selector:
    matchLabels:
      app: coroot-node-agent
  podMetricsEndpoints:
    - port: http
```

Make sure the PodMonitor matches `podMonitorSelector` defined in your Prometheus:
```yaml
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
...
spec:
  ...
  podMonitorNamespaceSelector: {}
  podMonitorSelector: {}
  ...
```
The special value `{}` allows Prometheus to watch all the PodMonitors from all namespaces. 

### Docker

```bash
docker run --detach --name coroot-node-agent \
    --privileged --pid host \
    -v /sys/kernel/debug:/sys/kernel/debug:rw \
    -v /sys/fs/cgroup:/host/sys/fs/cgroup:ro \
    ghcr.io/coroot/coroot-node-agent --cgroupfs-root=/host/sys/fs/cgroup
```

### Flags

```bash
usage: coroot-node-agent [<flags>]

Flags:
      --listen="0.0.0.0:80"  Listen address - ip:port or :port
      --cgroupfs-root="/sys/fs/cgroup"
                             The mount point of the host cgroupfs root
      --no-parse-logs        Disable container logs parsing
      --no-ping-upstreams    Disable container upstreams ping
      --track-public-network=TRACK-PUBLIC-NETWORK ...
                             Allow track connections to the specified IP networks, all private networks are allowed by default (e.g., Y.Y.Y.Y/mask)
      --provider=PROVIDER    `provider` label for `node_cloud_info` metric
      --region=REGION        `region` label for `node_cloud_info` metric
      --availability-zone=AVAILABILITY-ZONE
                             `availability_zone` label for `node_cloud_info` metric
```

## Metrics

The collected metrics are described [here](https://coroot.com/docs/metrics/node-agent).

## Coroot live demo

Coroot turns telemetry data gathered by node-agent into answers about app issues and how to fix them.

<img src="https://coroot.com/static/img/model.png" width="600" />

Live demo is available at [https://coroot.com/demo](https://coroot.com/demo).


## License

Coroot-node-agent is licensed under the [Apache License, Version 2.0](https://github.com/coroot/coroot-node-agent/blob/main/LICENSE).

The BPF code is licensed under the General Public License, Version 2.0.
