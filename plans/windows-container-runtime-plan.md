# Windows Container Runtime Plan

**Status:** Complete
**Parent:** `plans/windows-port-plan.md` M2
**Created:** 2026-06-16

## Goal

Discover Windows containers and emit stable `container_info{}` metrics
without relying on Linux cgroups. M2 assumes M0 cross-builds and M1
serves real node metrics.

M2 was validated on the Horde Windows VM after enabling the Windows
Containers and Hyper-V features and installing a Windows Docker Engine.
The real-runtime smoke used Hyper-V isolated Windows containers and a
Docker engine reporting `OSType=windows`.

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

Deferred beyond M2:

- Revisit containerd/CRI and HCS/HNS direct support after a Windows host
  with those runtimes is available for validation.

## Runtime Support Matrix

| Runtime / mode | Status | Notes |
|----------------|--------|-------|
| Docker Engine API with Windows containers | Implemented and smoke-tested | Uses the Docker API over the host's configured endpoint, normally `npipe:////./pipe/docker_engine`, and requires Docker `Ping.OSType` to be empty or `windows`. |
| Docker Desktop-provided Windows engine | Smoke-tested | Validated through the Docker Desktop package's Windows `dockerd.exe` registered as a headless Windows service. The engine reported `OSType=windows`, API `1.54`, and Hyper-V isolation. |
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
- 2026-06-17: Enabled Windows Containers and Hyper-V on the Horde
  Windows VM, installed Go `1.26.4` and Docker Engine `29.5.3`, and
  registered the Docker Desktop package's Windows `dockerd.exe` as a
  headless Windows service. `docker info` reported `OSType=windows`,
  API `1.54`, and Hyper-V isolation.
- 2026-06-17: Pulled
  `mcr.microsoft.com/windows/nanoserver:ltsc2025` and started three
  Hyper-V isolated containers: `coroot-m2-plain`,
  `coroot-m2-restart`, and `coroot-m2-k8s` with Kubernetes labels
  `io.kubernetes.pod.namespace=default`,
  `io.kubernetes.pod.name=api-7d9d6b6b7d-q8s2x`, and
  `io.kubernetes.container.name=api`.
- 2026-06-17: Built the Windows agent binary and ran it on the Horde
  Windows VM with `DOCKER_HOST=npipe:////./pipe/docker_engine`,
  `--listen=127.0.0.1:18080`, `--min-container-age=0s`, and
  `--wal-dir=C:\Temp\coroot-wal`. Scraping `/metrics` emitted
  `container_info{}` for `/docker/coroot-m2-plain`,
  `/docker/coroot-m2-restart`, and
  `/k8s/default/api-7d9d6b6b7d-q8s2x/api`.
- 2026-06-17: Restarted the agent and verified the emitted
  `container_id` set stayed
  `/docker/coroot-m2-plain,/docker/coroot-m2-restart,/k8s/default/api-7d9d6b6b7d-q8s2x/api`.
  Restarted `coroot-m2-restart`; Docker kept raw container ID
  `d17cfe995eeb499d432e8ccf303399e9d70fb2771c2cea7ffa643ef39d08a6d0`
  while its runtime PID changed from `1328` to `1344`, and the emitted
  logical `container_id` set remained unchanged.

## Acceptance Criteria

- [x] **M2-CRIT-1:** `make crossbuild-check` and `make test` pass.
- [x] **M2-CRIT-2:** The supported Windows runtime matrix is recorded
      in this plan or docs before the code is marked complete.
- [x] **M2-CRIT-3:** A Windows 11 scrape with 3+ supported containers
      emits non-zero `container_info{}` for each. Before final support
      validation, repeat this on Windows Server 2022 for every runtime
      mode listed as supported there.
- [x] **M2-CRIT-4:** `container_info{}` label keys match Linux.
- [x] **M2-CRIT-5:** Container logical identity is stable across agent
      restart and documented container restart scenarios.
- [x] **M2-CRIT-6:** Unsupported runtimes or isolation modes fail
      closed: they are logged and documented, not reported with
      unstable or invented identities.
