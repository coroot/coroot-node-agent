# Windows Port — Master Plan

**Status:** Draft (no beads filed yet)
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
  plan and bead with an upstream-style justification.
- **No new Linux features as part of this port.** If a Linux gap
  becomes obvious while building the Windows equivalent, file it as
  a `discovered-from` bead but do not bundle it into this plan.
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
   to share — primarily `ebpftracer/` — create a parallel package
   (`ebpfwin/`, `etwtracer/`) implementing the same constructor and
   collector interface. `main.go` selects between them via build tag.

The cardinal rule (see [`AGENTS.md`](../AGENTS.md) §"Build-tag
discipline"): **no `runtime.GOOS == "windows"` branching inside
shared files.** All platform divergence happens at compile time.

## 4. Windows tracing technology choice

The user's directive (2026-05-13): **use eBPF-for-Windows where it
covers the feature; fall back to ETW where it doesn't.** This drives
the parallel-package split:

- **`ebpfwin/`** — Microsoft eBPF-for-Windows. Used for the
  features it currently supports well: socket-level events,
  XDP-style packet inspection, simple kprobes. Detail mapping is a
  sub-plan (see §10).
- **`etwtracer/`** — Event Tracing for Windows. Used for everything
  eBPF-for-Windows can't reach: process lifecycle, file I/O, DNS
  client events, registry probes, Windows-specific events with no
  Linux analogue.

Both packages must expose the same Go interface to `main.go` so the
choice is invisible above the package boundary. A small dispatcher
inside the tracing layer (still build-tagged Windows-only) routes
each feature to whichever backend handles it.

## 5. Per-package map

This is the strategic plan, not a per-file checklist. Beads will
break it down further.

| Package        | Strategy           | Notes |
|----------------|--------------------|-------|
| `cgroup/`      | Build-tag sibling  | Linux cgroup v1/v2 file readers stay. Windows: Job Object + WMI process-group counters. |
| `common/`      | Mostly portable    | Audit each file. `kernel.go` is Linux-only — gate it; expose a thin `osversion` analogue for Windows. |
| `containers/`  | Mixed              | `containerd.go`, `dockerd.go` → portable in principle (Windows-native containerd / Docker Desktop); `crio.go`, `journald.go`, `systemd.go`, `cilium.go` → Linux-only, gated. `taskstats.go` → Linux-only (Netlink); Windows uses ETW. `l7.go` → mostly portable byte parsing. |
| `ebpftracer/`  | Linux-only         | No changes. Gated by build tag if not already implicit. |
| `ebpfwin/`     | **NEW**, Windows-only | eBPF-for-Windows-backed tracer. |
| `etwtracer/`   | **NEW**, Windows-only | ETW-backed tracer. |
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
parity. Beads track within-milestone work; this plan tracks
between-milestone gates.

### M0 — Scaffolding (blocks everything else)

- Add `//go:build linux` or `_linux.go` suffix to every existing
  Linux-coupled file that lacks a tag.
- Add empty `_windows.go` stubs that satisfy the Go API (return
  errors / zero values / no-op collectors).
- Add Makefile targets: `build-linux`, `build-windows`,
  `crossbuild-check`.
- Update CONTRIBUTING.md and README.md platform claims (note Windows
  is in-progress).

Exit gate: `make crossbuild-check` passes; Linux test suite (`make test`)
unchanged and green.

### M1 — Node-level metrics on Windows

- `main.go` split.
- `node/` Windows sibling (CPU, memory, disk, network counters).
- Basic `/metrics` HTTP endpoint serves on Windows with the same
  metric names where the underlying concept exists.

Exit gate: a Windows VM running the binary exposes `node_*` metrics
that a Prometheus scrape can ingest, with metric-name parity verified
against a Linux scrape.

### M2 — Container discovery on Windows

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

- `ebpfwin/` package built against eBPF-for-Windows for the features
  it supports (initial scope: TCP connect/listen/accept events).
- `etwtracer/` package built against ETW for the features
  eBPF-for-Windows doesn't cover (initial scope: process exec/exit,
  OOM-equivalent, DNS client events).
- Dispatcher (Windows-only) routes each tracer feature to the
  correct backend.
- Same metric names as the Linux `ebpftracer/`-emitted metrics where
  the concept exists.

Exit gate: integration test verifies `container_net_tcp_*`,
`container_net_listen_*`, `container_dns_requests_total`,
`container_oom_kills_total` are emitted on Windows with the same
metric-name surface as Linux.

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
fresh Windows Server 2022 host.

## 7. Open questions

These need triage before or during their respective milestones.
Each should become its own bead (type `task`, deps
`discovered-from:` this plan's M0 epic bead).

1. **Windows version floor.** Server 2019? 2022? 2025? Client SKUs?
   eBPF-for-Windows compatibility may dictate this.
2. **Container runtime support matrix.** Docker Desktop only?
   containerd-on-Windows only? Both? Hyper-V isolated vs
   process-isolated containers (different cgroup-equivalent stories)?
3. **eBPF-for-Windows feature coverage.** Concrete mapping from each
   Linux ebpftracer probe to either an eBPF-for-Windows program or
   an ETW provider. Sub-plan candidate (`plans/ebpfwin-coverage-plan.md`).
4. **Mixed-cluster k8s story.** How does a Kubernetes cluster with
   both Linux and Windows nodes deploy this agent? Two DaemonSets
   with `nodeSelector`s, or a single one with platform detection?
5. **TLS / mTLS for Prometheus scrape on Windows.** Cert store
   integration vs filesystem certs.
6. **CI matrix.** GitHub Actions Windows runners — do they have the
   features (eBPF-for-Windows driver, ETW provider registration
   privileges) we need? May need self-hosted runners.

## 8. Risks

- **eBPF-for-Windows maturity.** It's younger than Linux eBPF and
  the surface we need may not be fully supported. Mitigation: ETW
  fallback is by design, not by accident.
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
      `_linux.go` suffix, or adding an exported interface that an
      existing Linux implementation now satisfies. Enforced by code
      review and verified by `git log --follow` on a sample of
      Linux files at plan-close time.
- [ ] **CRIT-4**: A Windows binary built from the `windows-port`
      branch runs on Windows Server 2022, registers as a Windows
      service (or runs as a foreground process), and exposes
      `/metrics` containing `node_*` and `container_*` metrics.
      Verified by a documented smoke-test procedure in
      `docs/windows-quickstart.md`.
- [ ] **CRIT-5**: For metrics emitted on both Linux and Windows,
      metric names and label keys are identical. Verified by an
      integration test (or documented diff procedure) comparing
      Linux and Windows `/metrics` output for an equivalent
      workload.
- [ ] **CRIT-6**: README.md and CONTRIBUTING.md list Windows as a
      supported platform, with documented system requirements
      (Windows version floor, eBPF-for-Windows driver version,
      privileges required).
- [ ] **CRIT-7**: Each milestone (M0–M5) has its full bead set
      closed AND its documented exit gate demonstrably passed
      before the milestone is marked complete in this plan.
- [ ] **CRIT-8**: Every open question in §7 is either resolved
      (decision recorded in this plan or a sub-plan) or
      explicitly deferred (recorded as a bead in the backlog with
      `discovered-from:` linking back here).

## 10. Sub-plans (anticipated)

These don't exist yet; they're listed so future beads can reference
the expected paths.

- `plans/ebpfwin-coverage-plan.md` — concrete mapping from each
  Linux probe to eBPF-for-Windows or ETW. Drives M3.
- `plans/etw-tracer-plan.md` — ETW provider selection, session
  management, parsing strategy. Sub-plan of M3.
- `plans/windows-service-installer-plan.md` — packaging, MSI, and
  service-control story. Drives M5.
- `plans/windows-container-runtime-plan.md` — resolving the runtime
  support-matrix open question. Drives M2.

Each sub-plan must also carry its own Acceptance Criteria block per
[`AGENTS.md`](../AGENTS.md).
