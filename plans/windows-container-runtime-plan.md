# Windows Container Runtime Plan

**Status:** In Progress
**Parent:** `plans/windows-port-plan.md` M2
**Created:** 2026-06-16

## Goal

Discover Windows containers and emit stable `container_info{}` metrics
without relying on Linux cgroups. M2 assumes M0 cross-builds and M1
serves real node metrics.

M2 requires a Windows 11 VM with at least one supported Windows
container runtime for full development validation. The current Horde
Windows 11 VM has no Docker or containerd runtime installed, and its
Windows Containers / Hyper-V features are disabled. Installing or
enabling those features requires a host mutation and reboot, so the
current implementation slice is validated with Windows unit tests and
the no-runtime fail-closed scrape only.

Before Windows support is marked final, repeat the supported-runtime
smoke test on Windows Server 2022 unless the support matrix is
explicitly changed.

## Implementation Status

Implemented in this slice:

- Windows-only container registry collector in `containers/` that
  registers `container_info{}` and `container_restarts_total{}`.
- Docker Engine API source for Windows containers, using Docker API
  negotiation and container inspection.
- Runtime guard that rejects Docker engines reporting a non-Windows
  `OSType`, including Docker Desktop Linux-container / WSL modes.
- Stable logical IDs for Kubernetes, Kubernetes CronJobs, Docker
  Swarm, Nomad, and plain Docker containers.
- Fail-closed behavior when no supported runtime is present: the agent
  logs the unavailable runtime and continues serving non-container
  metrics without emitting invented `container_info{}` samples.

Still required before M2 is complete:

- Run the supported-runtime smoke with at least three real Windows
  containers.
- Validate identity stability across agent restarts and container
  restarts with a real runtime.
- Revisit containerd/CRI and HCS/HNS direct support after the Docker
  path is proven on a Windows host with containers enabled.

## Runtime Support Matrix

| Runtime / mode | Status | Notes |
|----------------|--------|-------|
| Docker Engine API with Windows containers | Implemented, pending real-runtime smoke | Uses the Docker API over the host's configured endpoint, normally `npipe:////./pipe/docker_engine`, and requires Docker `Ping.OSType` to be empty or `windows`. |
| Docker Desktop in Windows-container mode | Expected to work, pending smoke | Acceptable for Windows 11 development validation if the engine reports `OSType=windows`. |
| Docker Desktop in Linux-container / WSL mode | Unsupported, fail closed | Rejected because it reports a Linux engine and would expose Linux containers, not Windows host containers. |
| containerd / CRI on Windows | Deferred | Not implemented in this slice. Add a source only after a host with Windows containerd / CRI is available for validation. |
| HCS / HNS direct fallback | Deferred | Use later for Windows-specific lifecycle or network gaps that Docker/containerd cannot expose reliably. |
| No supported runtime installed | Supported fail-closed state | The agent logs the missing runtime and emits no container metrics. |

## Identity Model

Linux currently derives identity from cgroup paths and then enriches it
with runtime metadata. Windows must invert that flow:

- Runtime container ID is the primary stable raw identifier.
- Kubernetes labels, when present, produce the same logical app ID shape
  as Linux: `/k8s/<namespace>/<pod>/<container>`.
- Docker Swarm labels, when present, produce the same logical app ID
  shape as Linux: `/swarm/<namespace>/<service>/<task>`.
- Plain Docker containers use `/docker/<container-name>` when the name
  is stable and non-empty.
- Plain containerd containers will use
  `/containerd/<container-name-or-id>` once the deferred containerd
  source is implemented, unless a more specific CRI/Kubernetes
  identity is available.
- Windows has no systemd service equivalent; `container_info` labels
  `systemd_triggered_by` and `systemd_type` must be emitted as empty
  strings on Windows.

## M2 Metric Scope

Required:

- `container_info{image,systemd_triggered_by,systemd_type}`
- `container_restarts_total` when restart count is available from the
  runtime; otherwise document omission for Windows.
- Container labels used by existing `app_id` wrapping must remain
  stable across agent restarts and container restarts.

Deferred to later milestones or sub-plans:

- Per-container CPU/memory/disk limits and usage if they require a
  separate Job Object/HCS accounting design.
- TCP, DNS, L7, and OOM metrics; these belong to M3.
- Log-pattern metrics; these belong to M4.

## Verification Procedure

On a Windows 11 host:

1. Start at least three Windows containers: one plain runtime container,
   one restarted container, and one Kubernetes/CRI-shaped container if
   that runtime is in scope for the milestone.
2. Run the agent and scrape `/metrics`.
3. Verify `container_info{}` appears for all supported containers.
4. Restart the agent and verify logical container IDs and `app_id`
   labels do not change.
5. Restart one container and verify the new runtime instance is mapped
   to the expected logical identity.

## Verification Log

- 2026-06-16: `make crossbuild-check` and `make test` succeeded.
- 2026-06-16: `GOOS=windows go build ./...` succeeded.
- 2026-06-16: Windows `./containers` test binary passed on the Horde
  Windows 11 VM.
- 2026-06-16: Agent smoke on the Horde Windows 11 VM with no Docker or
  containerd runtime installed served `node_info` and emitted no
  `container_info{}` samples, matching the fail-closed requirement.

## Acceptance Criteria

- [x] **M2-CRIT-1:** `make crossbuild-check` and `make test` pass.
- [x] **M2-CRIT-2:** The supported Windows runtime matrix is recorded
      in this plan or docs before the code is marked complete.
- [ ] **M2-CRIT-3:** A Windows 11 scrape with 3+ supported containers
      emits non-zero `container_info{}` for each. Before final support
      validation, repeat this on Windows Server 2022 for every runtime
      mode listed as supported there.
- [x] **M2-CRIT-4:** `container_info{}` label keys match Linux.
- [ ] **M2-CRIT-5:** Container logical identity is stable across agent
      restart and documented container restart scenarios.
- [x] **M2-CRIT-6:** Unsupported runtimes or isolation modes fail
      closed: they are logged and documented, not reported with
      unstable or invented identities.
