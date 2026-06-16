# Windows Container Runtime Plan

**Status:** Draft
**Parent:** `plans/windows-port-plan.md` M2
**Created:** 2026-06-16

## Goal

Discover Windows containers and emit stable `container_info{}` metrics
without relying on Linux cgroups. M2 assumes M0 cross-builds and M1
serves real node metrics.

M2 requires a Windows 11 VM with at least one supported Windows
container runtime for development validation. Before Windows support is
marked final, repeat the supported-runtime smoke test on Windows Server
2022 unless the support matrix is explicitly changed.

## Runtime Support Order

1. **Docker Engine on Windows Server** if available. Use the Docker API
   for container ID, name, image, labels, mounts, log path, network
   bindings, and process IDs where exposed.
2. **containerd on Windows** if available. Use the containerd API and
   CRI metadata for Kubernetes labels, image, log path, and task/PID
   data.
3. **HCS/HNS fallback** for Windows-specific lifecycle, process, and
   network metadata that Docker/containerd do not expose reliably.

Docker Desktop may be used for Windows 11 development validation. The
final supported runtime matrix must state which runtime/isolation modes
are supported on Windows 11 and which are supported on Windows Server
2022.

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
- Plain containerd containers use `/containerd/<container-name-or-id>`
  unless a more specific CRI/Kubernetes identity is available.
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

## Acceptance Criteria

- [ ] **M2-CRIT-1:** `make crossbuild-check` and `make test` pass.
- [ ] **M2-CRIT-2:** The supported Windows runtime matrix is recorded
      in this plan or docs before the code is marked complete.
- [ ] **M2-CRIT-3:** A Windows 11 scrape with 3+ supported containers
      emits non-zero `container_info{}` for each. Before final support
      validation, repeat this on Windows Server 2022 for every runtime
      mode listed as supported there.
- [ ] **M2-CRIT-4:** `container_info{}` label keys match Linux.
- [ ] **M2-CRIT-5:** Container logical identity is stable across agent
      restart and documented container restart scenarios.
- [ ] **M2-CRIT-6:** Unsupported runtimes or isolation modes fail
      closed: they are logged and documented, not reported with
      unstable or invented identities.
