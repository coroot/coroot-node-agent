# Windows Port — Master Plan

**Status:** Draft
**Owner:** @shedwards
**Created:** 2026-05-13

## 1. Goal

Add Windows support to `coroot-node-agent` while keeping the existing
Linux code paths unchanged. Feature parity with the Linux build is
the eventual target, delivered in milestones.

## 2. Non-goals

- **No refactor of Linux code for the port's sake.** Linux files are
  not restructured, renamed, or "harmonized" just because Windows
  needs something different. Only mechanical edits are allowed on
  Linux files: adding a `//go:build linux` header line, or renaming
  to a `_linux.go` suffix. Anything beyond that requires a separate
  plan with an upstream-style justification.
- **No new Linux features as part of this port.** If a Linux gap
  becomes obvious while building the Windows equivalent, record it as
  follow-up work but do not bundle it into this plan.
- **No upstream contribution back to `coroot/coroot-node-agent`** is
  promised by this plan. Upstreaming is a separate decision and a
  separate plan if/when it happens.

## 3. Approach

Three mechanisms, in order of preference:

1. **No change.** Code that's already platform-agnostic (most of
   `prom/`, `tracing/`, `flags/`, parts of `common/`) needs nothing.
2. **Build-tag sibling files.** For files that are Linux-coupled but
   small in scope, gate the existing file with `//go:build linux`
   (or `_linux.go` suffix) and add a `_windows.go` sibling with the
   same exported Go API. This is the workhorse pattern.
3. **Parallel package.** For subsystems that are too deeply coupled
   to share — primarily `ebpftracer/` — create a Windows parallel
   package (`etwtracer/`) implementing the same event/collector
   contract consumed by the container/tracing layer. Optional
   experimental backends (`ebpfwin/`, WFP driver packages) may be
   added later only behind the same contract and their own sub-plans.

The cardinal rule (see [`AGENTS.md`](../AGENTS.md) §"Build-tag
discipline"): **no `runtime.GOOS == "windows"` branching inside
shared files.** All platform divergence happens at compile time.

## 4. Windows tracing technology choice

Decision update (2026-06-16): **ETW is the required Windows tracing
backend.** eBPF-for-Windows is promising but still too immature for
this port's core acceptance criteria, so the mainline Windows port
must not depend on it.

- **`etwtracer/`** — Event Tracing for Windows. This is the primary
  Windows tracer for M3. Initial scope: process lifecycle, TCP
  connect/listen/accept visibility where ETW providers expose it, DNS
  client events, file I/O, registry events, and Windows-specific
  lifecycle events with no Linux analogue.
- **PDH / Performance Counters** — node-level counters for M1. These
  replace Linux `/proc` and `/sys` reads for CPU, memory, disk, and
  network counters; they are not part of the tracing backend but are
  the expected source for `node_*` metrics.
- **HCS / HNS / runtime APIs** — container discovery and lifecycle
  data for M2. Docker/containerd APIs remain preferred where they
  expose stable metadata; Host Compute Service and Host Network
  Service fill Windows-specific gaps.
- **`ebpfwin/`** — optional, experimental only. Do not use it for any
  M0-M5 exit gate unless a future `plans/ebpfwin-experiment-plan.md`
  proves the required program types, deployment model, driver
  requirements, and support matrix.
- **WFP fallback** — optional, driver-level fallback for network gaps.
  If ETW cannot provide reliable per-container socket attribution or
  packet-level visibility, create a separate WFP sub-plan before
  adding a driver package. WFP is not part of the first Windows port
  unless M3 proves it is unavoidable.

The Linux `ebpftracer/` package remains Linux-only. Windows tracing
packages must expose a platform-neutral event/collector contract to
`containers/` and the tracing layer so the rest of the agent does not
know whether events came from Linux eBPF, Windows ETW, or a future WFP
fallback.

## 5. Per-package map

This is the strategic plan, not a per-file checklist. Implementation
work will break it down further.

| Package        | Strategy           | Notes |
|----------------|--------------------|-------|
| `cgroup/`      | Build-tag sibling  | Linux cgroup v1/v2 file readers stay. Windows: Job Object + WMI process-group counters. |
| `common/`      | Mostly portable    | Audit each file. `kernel.go` is Linux-only — gate it; expose a thin `osversion` analogue for Windows. |
| `containers/`  | Mixed              | `containerd.go`, `dockerd.go` → portable in principle (Windows-native containerd / Docker Desktop); `crio.go`, `journald.go`, `systemd.go`, `cilium.go` → Linux-only, gated. `taskstats.go` → Linux-only (Netlink); Windows uses ETW plus HCS/HNS/runtime APIs. `l7.go` → mostly portable byte parsing. |
| `ebpftracer/`  | Linux-only         | No changes. Gated by build tag if not already implicit. |
| `etwtracer/`   | **NEW**, Windows-only | Required ETW-backed tracer for M3. |
| `ebpfwin/`     | Optional, Windows-only | Experimental eBPF-for-Windows backend only after a separate sub-plan proves coverage and supportability. |
| `wfpdriver/` or `wfpnet/` | Optional, Windows-only | Future WFP fallback for packet/socket visibility if ETW cannot satisfy M3 network gates. Requires a driver/signing/deployment sub-plan before implementation. |
| `flags/`       | Portable           | Likely no changes. |
| `gpu/`         | Mostly portable    | NVML works on both Linux and Windows. Verify build, gate any `/proc`/`/sys` reads. |
| `java-agent/`  | Portable           | Java agent is cross-platform. |
| `jvm/`         | Audit              | Process inspection bits may need a Windows sibling. |
| `logs/`        | Build-tag sibling  | File-tailing portable; journald and dockerd JSON Linux-only. Add Windows Event Log later (sub-plan). |
| `main.go`      | Build-tag split    | `uname()`, `machineID()`, `systemUUID()`, kernel-version-gate move to `main_linux.go`. Windows analogues (registry MachineGuid, `GetVersionEx`, SMBIOS via WMI) in `main_windows.go`. Orchestration stays in `main.go`. |
| `manifests/`   | Add Windows variants | Container-image YAMLs need Windows-node variants or `nodeSelector`s. Sub-plan. |
| `node/`        | Build-tag sibling  | CPU/mem/disk/net counters: Linux files keep `/proc`/`/sys` readers; Windows sibling uses PDH (Performance Data Helper) and WMI. |
| `pinger/`      | Build-tag sibling  | ICMP raw-socket plumbing differs on Windows. |
| `proc/`        | Build-tag sibling  | `/proc` readers are Linux-only. Windows uses `NtQuerySystemInformation` / WMI for the analogous data. |
| `profiling/`   | Linux-only (v1)    | Pyroscope eBPF profiler stays Linux-only. Windows stub returns no-op collector. Future: Windows profiler is its own plan. |
| `prom/`        | Portable           | No changes expected. |
| `tracing/`     | Portable           | OTel SDK is cross-platform. |

## 6. Milestones

Each milestone is a chunk that lands a coherent slice of feature
parity. This plan tracks between-milestone gates.

### M0 — Scaffolding (complete)

- Follow `plans/windows-m0-scaffolding-plan.md`.
- Add `//go:build linux` or `_linux.go` suffix to every existing
  Linux-coupled file that lacks a tag.
- Move compile-blocking Linux helpers out of `main.go` so the shared
  startup path can build for both `GOOS=linux` and `GOOS=windows`.
- Add empty `_windows.go` stubs that satisfy the Go API. Startup-path
  stubs (`containers/`, `profiling/`, and other packages initialized
  before `/metrics`) must initialize successfully as no-op collectors
  so M1 can serve node metrics before M2/M3 are complete. APIs not
  used during startup may return explicit "not implemented on Windows"
  errors.
- Add Makefile targets: `build-linux`, `build-windows`,
  `crossbuild-check`.
- Update CONTRIBUTING.md and README.md platform claims (note Windows
  is in-progress).

Exit gate: `make crossbuild-check` passes; Linux test suite (`make test`)
unchanged and green.

### M1 — Node-level metrics on Windows

- Follow `plans/windows-node-metrics-plan.md`.
- Complete the Windows implementations behind the `main.go` split
  created during M0.
- `node/` Windows sibling (CPU, memory, disk, network counters).
- Basic `/metrics` HTTP endpoint serves on Windows with the same
  metric names where the underlying concept exists.

Exit gate: a Windows VM running the binary exposes `node_*` metrics
that a Prometheus scrape can ingest, with metric-name parity verified
against a Linux scrape.

### M2 — Container discovery on Windows

- Follow `plans/windows-container-runtime-plan.md`.
- `containers/dockerd.go` and `containers/containerd.go` work
  against Windows-native Docker and containerd runtimes.
- Linux-only sources (`crio.go`, `journald.go`, `systemd.go`,
  `cilium.go`) are build-tagged out of the Windows binary.
- `container_info{}` metric labels are stable across container
  restarts.

Exit gate: a Windows host running 3+ containers under Docker (or
containerd) shows non-zero `container_info{}` with stable container
IDs, image labels, and PID mappings.

### M3 — Tracing layer (the substantial one)

- Follow `plans/etw-tracer-plan.md`.
- `etwtracer/` package consumes the chosen ETW providers for process
  exec/exit, TCP connect/listen/accept, DNS client events, and any
  file/registry events needed by the container/logging layers.
- Windows tracing events are normalized into the same internal event
  contract used by Linux `ebpftracer/` callers, without importing
  Linux-only `ebpftracer` types into Windows builds.
- Same metric names as the Linux `ebpftracer/`-emitted metrics where
  the Windows concept exists and the data quality is comparable.
- If ETW cannot satisfy a required network metric with reliable
  per-container attribution, record the gap and create a WFP fallback
  sub-plan before adding any driver code.
- `ebpfwin/` remains out of the M3 critical path. It may be tested in
  parallel only under a separate experimental sub-plan.

Exit gate: integration test verifies `container_net_tcp_*`,
`container_net_listen_*`, and `container_dns_requests_total` are
emitted on Windows with the same metric-name surface as Linux.
`container_oom_kills_total` is emitted only if the M3 sub-plan defines
a precise Windows source event and semantic equivalent; otherwise the
omission is documented as a non-parity item.

### M4 — Logs and process detail

- Log tailing on Windows (files and Docker JSON driver portable;
  add Windows Event Log).
- `proc/` Windows analogue extended for any data needed by
  `containers/process.go` that wasn't already covered in M2.
- `profiling/` left as a no-op stub on Windows (separate future plan).

Exit gate: log-pattern extraction emits `container_log_messages_total`
on Windows from a containerized app writing to stdout.

### M5 — Packaging and deployment

- Windows service installer (likely via `golang.org/x/sys/windows/svc`).
- Container image for Windows nodes (or `nodeSelector` story if we
  ship a Linux-pod-on-Windows-node hybrid).
- `manifests/` updated for Windows-node DaemonSet.

Exit gate: a documented install procedure works end-to-end on a
fresh supported Windows host. The normal development validation host is
Windows 11; final release/support validation must also include Windows
Server 2022 unless the support matrix is explicitly changed before M5.

## 7. Open questions

These need triage before or during their respective milestones.
Each should become its own follow-up task or sub-plan before the
relevant milestone begins.

1. **Windows version floor.** Default development validation target is
   Windows 11 because that is the VM environment normally available on
   this branch. Final support validation should include Windows Server
   2022 before the port is marked supported. The M1/M2 sub-plans may
   explicitly expand to Server 2019, Server 2025, or additional client
   SKUs if the required PDH, ETW, HCS/HNS, and runtime APIs are
   verified there.
2. **Container runtime support matrix.** Docker Desktop only?
   containerd-on-Windows only? Both? Hyper-V isolated vs
   process-isolated containers (different cgroup-equivalent stories)?
3. **ETW provider coverage.** Concrete mapping from each Linux
   `ebpftracer` event and container metric to an ETW provider, HCS/HNS
   source, runtime API, or documented omission. Tracked in
   `plans/etw-tracer-plan.md`.
4. **Mixed-cluster k8s story.** How does a Kubernetes cluster with
   both Linux and Windows nodes deploy this agent? Two DaemonSets
   with `nodeSelector`s, or a single one with platform detection?
5. **TLS / mTLS for Prometheus scrape on Windows.** Cert store
   integration vs filesystem certs.
6. **CI matrix.** GitHub Actions Windows runners — do they have the
   ETW session privileges and container runtime support needed for
   meaningful integration tests? May need self-hosted runners.
7. **WFP fallback threshold.** What exact failed ETW acceptance test
   justifies adding a signed WFP driver package instead of omitting or
   approximating the metric?

## 8. Risks

- **ETW attribution gaps.** ETW may expose the event but not enough
  container/process/network context to match Linux metric semantics.
  Mitigation: require explicit per-metric source mapping in the M3
  sub-plan and document omissions rather than emitting misleading
  parity metrics.
- **WFP driver complexity.** A WFP fallback would add kernel-driver
  code, signing, installer, upgrade, and support burden. Mitigation:
  WFP requires a separate sub-plan and a failed ETW acceptance test
  before implementation.
- **eBPF-for-Windows maturity.** It remains useful to watch, but it is
  no longer on the critical path. Mitigation: keep `ebpfwin/`
  experimental and outside required acceptance criteria until a
  dedicated sub-plan proves it.
- **Metric name drift between Linux and Windows.** If a Windows
  source can only approximate a Linux metric (e.g. delay-accounting
  has no direct equivalent), we either emit a less-precise variant
  with a label or omit. Decided per-metric in M1–M4 sub-plans.
- **Upstream merge conflicts.** Coroot upstream evolves Linux code
  during the port. Mitigation: the build-tag discipline rule makes
  this a non-issue for files we don't touch; conflicts will be
  isolated to files where we added a build-tag header.

## 9. Acceptance Criteria

- [ ] **CRIT-1**: `GOOS=linux go build ./...` and
      `GOOS=windows go build ./...` both succeed from a clean
      checkout. Enforced by the `crossbuild-check` Makefile target
      added in M0.
- [ ] **CRIT-2**: All pre-existing Linux tests still pass on a
      Linux host (`make test` is green). Regression-free port.
- [ ] **CRIT-3**: No Linux source file is functionally modified by
      this port. Permitted Linux-side changes are limited to:
      adding a `//go:build linux` header line, renaming to
      `_linux.go` suffix, or adding new shared interface/adaptor
      files that existing Linux implementations satisfy without body
      changes. Enforced by code review and verified by `git log
      --follow` on a sample of Linux files at plan-close time.
- [ ] **CRIT-4**: A Windows binary built from the `windows-port`
      branch runs on Windows 11 during development validation and on
      Windows Server 2022 before final support validation, registers as
      a Windows service (or runs as a foreground process), and exposes
      `/metrics` containing `node_*` and `container_*` metrics. Verified
      by a documented smoke-test procedure in
      `docs/windows-quickstart.md`.
- [ ] **CRIT-5**: For metrics emitted on both Linux and Windows,
      metric names and label keys are identical. Verified by an
      integration test (or documented diff procedure) comparing
      Linux and Windows `/metrics` output for an equivalent
      workload.
- [ ] **CRIT-6**: README.md and CONTRIBUTING.md list Windows as a
      supported platform, with documented system requirements
      (Windows version floor, ETW/PDH/HCS privileges required, and
      any optional WFP or eBPF-for-Windows driver requirements if
      those backends are enabled).
- [ ] **CRIT-7**: Each milestone (M0–M5) has its implementation
      work complete AND its documented exit gate demonstrably passed
      before the milestone is marked complete in this plan. Each
      milestone status update must cite the command, test, or manual
      smoke-test note that proved the gate.
- [ ] **CRIT-8**: Every open question in §7 is either resolved
      (decision recorded in this plan or a sub-plan) or
      explicitly deferred (recorded as follow-up work with a link
      back here).

## 10. Sub-plans (anticipated)

These carry the implementation details that are too specific for the
master plan.

- `plans/windows-m0-scaffolding-plan.md` — concrete compile-blocker
  inventory, startup-path no-op rules, and cross-build gate. Drives
  M0.
- `plans/windows-node-metrics-plan.md` — Windows source mapping for
  required `node_*` metrics and the M1 smoke test. Drives M1.
- `plans/windows-container-runtime-plan.md` — Windows runtime support
  matrix, identity model, and `container_info{}` stability rules.
  Drives M2.
- `plans/etw-tracer-plan.md` — ETW provider selection, session
  management, event normalization, and metric/source mapping. Drives
  M3.
- `plans/windows-network-fallback-plan.md` — WFP driver feasibility,
  signing/deployment story, and the exact ETW gaps that justify a
  driver fallback. Optional; only created if M3 proves ETW is
  insufficient.
- `plans/ebpfwin-experiment-plan.md` — optional eBPF-for-Windows
  experiment. Must prove supported program types, deployment, and
  support matrix before any `ebpfwin/` code is used by production
  Windows builds.
- `plans/windows-service-installer-plan.md` — packaging, MSI, and
  service-control story. Drives M5.
- `plans/windows-container-runtime-plan.md` — resolving the runtime
  support-matrix open question. Drives M2.

Each sub-plan must also carry its own Acceptance Criteria block per
[`AGENTS.md`](../AGENTS.md).
