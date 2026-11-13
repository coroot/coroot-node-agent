# Kernel tests

`run.sh` boots the agent on a specific Linux kernel and checks that it works there.
It exists because an eBPF program that loads on one kernel can be rejected by the verifier of another,
and the agent does not start in that case.

```
kerneltest/run.sh <agent-image> <kernel>
```

For example:

```
docker build -t coroot-node-agent:test .
kerneltest/run.sh coroot-node-agent:test 5.4
kerneltest/run.sh coroot-node-agent:test ghcr.io/coroot/ci-kernels:4.18-el8
```

## How it works

1. The kernel comes from a container image that carries `/boot/vmlinuz` and, for kernels that need them, modules in `/lib/modules`. There are two sources:
   * Upstream kernels from [cilium/ci-kernels](https://github.com/cilium/ci-kernels), built from kernel.org sources. Pass a tag of `ghcr.io/cilium/ci-kernels`, such as `5.4`, `6.12`, `stable` or `mainline`.
   * Distribution kernels from [coroot/ci-kernels](https://github.com/coroot/ci-kernels), repackaged from the distributions' own packages. Pass a full image reference, such as `ghcr.io/coroot/ci-kernels:4.18-el8`.
2. The agent's container image is exported and packed into an initramfs together with the kernel modules. The `init` script from this directory becomes PID 1.
3. QEMU boots the kernel with that initramfs. No disk image or operating system install is involved.
4. `init` loads the conntrack modules if the kernel has them as modules, then starts systemd from the agent image. systemd runs the agent, an HTTP server and an HTTP client as services, so the agent sees them the way it sees services on a real host.
5. The test passes when the agent serves `/metrics` and reports both the TCP connections (`container_net_tcp_successful_connects_total`, `container_net_tcp_listen_info`) and the HTTP requests (`container_http_requests_total`, `container_http_inbound_requests_total`) between the two services. On 3.x kernels the agent has no L7 tracing, so only the TCP connections are required there.

The script prints `KERNELTEST PASS` or `KERNELTEST FAIL` followed by the agent log and exits with 0 or 1.

## Requirements

Docker is the only requirement. If `qemu-system-x86_64` is not installed, QEMU runs in a container.
With `/dev/kvm` a run takes about a minute. Without it QEMU falls back to emulation, which is several times slower.

## CI

The `Kernels` workflow runs the test for every kernel in its matrix on pull requests, on pushes to `main`, and before a release is published.
To add a kernel, add its tag or image reference to the matrix in `.github/workflows/kernels.yml`.

## Limitations

* amd64 only.
* Upstream kernels older than 5.2 are not in the matrix. Their verifier limits programs to 4096 instructions, which the L7 programs exceed. The old kernels the agent supports are the RHEL ones, which carry backported eBPF changes.
* There is no container runtime in the VM. The test processes are systemd services, so container discovery through Docker, containerd or CRI-O is not tested.
