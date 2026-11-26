# Node.js kernel tests

These tests check the Node.js TLS tracing of the agent on every kernel of the CI matrix, on amd64 and arm64,
with the Node.js builds that users run. The generic kernel test in the parent directory proves that the eBPF
programs load and that plain HTTP is traced. These tests run the Node.js uprobes and check what they report.

```
kerneltest/nodejs/kernels/build.sh                      # once: the arm64 kernels
kerneltest/nodejs/matrix.sh                             # every kernel, amd64 and arm64
kerneltest/nodejs/run.sh arm64 local/ci-kernels:6.1     # one kernel
NO_BUILD=1 kerneltest/nodejs/run.sh amd64 ghcr.io/coroot/ci-kernels:4.18-el8
```

## What can break, and what varies

The tracing can break in three places, so the tests vary all three:

- **The CPU architecture.** The probes read function arguments from registers and find return instructions, and both
  differ between amd64 and arm64. The agent also loads a different eBPF build per architecture.
- **The kernel.** The verifier, the eBPF build that the agent picks by kernel version, and the way uprobes attach differ
  between kernels. Distribution kernels carry backported eBPF features.
- **The Node.js build.** The probes attach to C++ symbols of Node.js and to OpenSSL. Where those symbols are depends on
  the build: in the `node` executable, in `libnode.so`, or in a shared `libssl.so`. The C library and the Node.js
  version change them too.

The first two vary per VM, the third does not need its own VM. Every VM runs every Node.js build, so a run of the matrix
covers every combination.

| Node.js build | C++ symbols | OpenSSL | C library |
|---|---|---|---|
| `official-18`, `-20`, `-22`, `-24` (`node:<version>-bookworm-slim`) | `node` | in `node` | glibc |
| `official-22-alpine` (`node:22-alpine`) | `node` | in `node` | musl |
| `debian-12`, `ubuntu-24.04` (the `nodejs` package) | `libnode.so` | `libssl.so.3` | glibc |
| `ubi-9` (`ubi9/nodejs-22-minimal`) | `libnode.so` | `libssl.so.3` | glibc |
| `alpine-3.20` (the `nodejs` package) | `node` | `libssl.so.3` | musl |

## What a VM runs

`Dockerfile` builds the root filesystem: Debian with systemd and the agent, cross-compiled from the working tree, and
one root per Node.js build under `/os`, taken from its image. `init` starts the agent and, for every root, an HTTPS
server and a client as systemd services with `RootDirectory=`, so the agent sees them as it sees containers. The server
and the client of a root run one executable, as containers of one image do: the uprobes are registered on the file and
fire in both processes.

A client sends two requests over each connection and then opens a new one. The first request of a connection is
written before the agent has seen a read on it, so it is traced through `TLSWrap::EncOut`; the second is traced
through the binding that the reads made. Each client writes the number of requests it completed to a file.

One more pair, `addon`, runs a native addon (`app/addon.c`) that does its own TLS over a socket BIO, as `pg-native`
does. It also sends two requests over each connection, so the first one is written before any read on the connection.
In the same tick the client writes a plain HTTP request through Node.js, so a TLS request bound to the wrong socket
shows up under the plain connection.

The test pauses the clients, takes a snapshot of the metrics and the files, resumes the clients, and takes a second
snapshot the same way 30 seconds later. It passes when:

- for every root and for `addon`, the clients completed at least 10 HTTPS requests between the snapshots, and the
  agent reports that number for the client and for the server, with a difference of at most 5% and one more. The
  agent misses some first requests of new connections, with or without TLS, and the 5% covers that;
- the addon client reports at least 10 HTTP requests and no HTTPS request under the HTTP connection;
- the servers of the official builds report a non-zero `container_nodejs_event_loop_blocked_time_seconds_total`.
  The other builds link libuv dynamically, and the agent does not probe it there;
- the kernel log has no oops. An oops in an eBPF program kills only the thread that hit the probe, so the reason
  names it: for a Node.js process it is usually the main thread, and the process stops answering without exiting.
  Soft lockups and warnings do not fail the test, because an emulated VM on a busy host can report them.

On 3.x kernels the agent has no L7 tracing, so the test only checks that the agent starts.

When a check fails, the log shows the metrics, the state and the log of every service, and the agent's log about it.
For a scenario that completed no request, it also shows the sockets of its port and, twice a few seconds apart, the
state, CPU time and kernel wait of every thread of the client and the server, so that a process that hangs or spins
can be told from one that waits for the network.

## Kernels

amd64 uses the images of the Kernels workflow: `ghcr.io/cilium/ci-kernels` for upstream kernels and
`ghcr.io/coroot/ci-kernels` for distribution kernels.

Neither publishes the arm64 kernels the tests need, so `kernels/build.sh` builds them as `local/ci-kernels:<tag>`,
one per tag of the matrix, as listed in `kernels/arm64.txt`:

- An upstream kernel is built from kernel.org with the configuration of cilium/ci-kernels, plus conntrack netlink
  (`kernels/config-arm64`). The arm64 builds of cilium/ci-kernels do not have it, and the agent does not start
  without it. The arm64 defconfig leaves it out, while the x86_64 defconfig enables it. cilium/ci-kernels no longer
  builds 5.4 and 7.0, and their last builds are amd64 only. The versions are fixed in `kernels/arm64.txt`, while the
  amd64 tags `stable` and `mainline` move to newer kernels: the log of each run names the kernel it booted.
- A distribution kernel is repackaged from the distribution's arm64 packages by coroot/ci-kernels. CentOS 7 shipped
  4.18 on arm64, so `3.10-el7` is that kernel, and the agent has L7 tracing there.

Two arm64 kernels fail with the agent of `main` as well, so the failures are not about Node.js:

- `5.15`: the agent exits at start, because netlink fails (`failed to get network interfaces: protocol not supported`,
  then `netlink receive: no such file or directory`). The build has the same network configuration as `5.10`, and a
  build with the compiler of Debian 11 fails the same way.
- `5.4` and `5.4-ubuntu20.04`: the agent starts but reports no L7 request, not even plain HTTP.

Building all of them takes about an hour: the upstream kernels compile in 4-10 minutes each on 6 CPUs, the
distribution kernels only unpack packages.

## Running

| Variable | Default | Meaning |
|---|---|---|
| `NO_BUILD` | | `1` reuses the root filesystem of an earlier run |
| `TIMEOUT` | 1800 | seconds one VM may run |
| `MEMORY`, `CPUS` | `8G`, 4 | the size of a VM. The root filesystem is about 2 GB in memory |
| `CACHE` | `~/.cache/coroot-node-agent-nodetest` | where the root filesystems are kept, about 700 MB per architecture |
| `JOBS` | 2 | VMs that `matrix.sh` runs at once, each with `CPUS` host threads |
| `OUT` | a new temporary directory | where `matrix.sh` keeps the console logs |
| `ARM64_KERNELS_REPO` | `local/ci-kernels` | where the arm64 kernels come from |

`matrix.sh` prints one line per architecture and kernel, `PASS` or `FAIL` with the reason, and exits with 1 if a kernel
other than `mainline` fails. A missing kernel image is a failure.

The root filesystem embeds the eBPF programs from `ebpftracer/ebpf.go`, so after a change to the C sources run
`make -C ebpftracer build` first.

The scripts need Docker and QEMU (`qemu-system-x86_64`, `qemu-system-aarch64`), and on macOS also `timeout`
(`brew install qemu coreutils`). QEMU uses KVM when the VM has the host's architecture, and HVF for arm64 VMs on Apple
silicon. Otherwise it emulates the CPU: an amd64 VM takes about 6 minutes on an M1 Pro, against 4-5 minutes for an
arm64 VM with HVF. Apple silicon has no 64K pages, so the arm64
RHEL 7 and 8 kernels are always emulated.
