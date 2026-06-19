# Windows Support Hardening Plan

**Status:** Implemented; Server 2022 validation blocked pending host
**Parent:** `plans/windows-port-plan.md` final support and future work
**Created:** 2026-06-18

## Goal

Close the support-readiness work after M0-M5 by adding repeatable
validation artifacts, an explicit support matrix, packaging scripts,
Windows CI coverage, and bounded implementations for safe Windows
process/profiling/log follow-up work.

## Requested Scope

Final-support work:

- Validate on Windows Server 2022 in addition to the Windows 11 VM.
- Lock the supported platform and runtime matrix.
- Add a repeatable Linux-vs-Windows metric label compatibility check.
- Move user docs toward a support-ready state without overstating
  Server 2022 validation.

Future-work items:

- Packaging polish.
- More log/process sources.
- Windows profiling.
- CI.

## Implementation Slices

1. **Support matrix and validation tooling.**
   Add `docs/windows-support-matrix.md` and a metric label compatibility
   tool that compares two Prometheus scrape files. Server 2022
   validation remains blocked until a Server 2022 host is available.
2. **Packaging polish.**
   Add PowerShell install/uninstall scripts that wrap the documented
   Windows service procedure and keep service flags explicit. Native MSI
   release packaging is tracked separately in
   `plans/windows-msi-release-plan.md`.
3. **Process detail.**
   Implement Windows `proc.ListPids` and best-effort `proc.GetCmdline`
   via Windows process APIs. This gives Windows code real process
   inventory data without inventing container cgroup semantics.
4. **Profiling.**
   Keep CPU/heap profiling disabled on Windows for now, but make the
   unsupported state explicit in docs and tests. Windows eBPF/ETW
   profiling requires a separate profiler design before any metric is
   emitted.
5. **CI.**
   Add GitHub-hosted Windows compile/unit coverage and a separate
   self-hosted Windows integration workflow for ETW/container/service
   smokes.

## Blockers

- A Windows Server 2022 VM or host is required to complete final support
  validation. The currently provided validation host reports
  `Microsoft Windows 11 Enterprise`, version `10.0.26100`, product type
  `1` on 2026-06-18.
- Windows HostProcess Kubernetes validation requires a Windows Server
  Kubernetes node and a publishable Windows image tag.
- Windows DNS/listen/failure network metrics remain owned by
  `plans/windows-network-fallback-plan.md`.

## Verification Log

- 2026-06-18: The available Windows validation host reported
  `Microsoft Windows 11 Enterprise`, version `10.0.26100`, product type
  `1`. This is not a Windows Server 2022 host, so
  **HARDEN-CRIT-1 remains blocked**.
- 2026-06-18: `make lint`, `make test`, `make crossbuild-check`, and
  `go test ./tools/metriclabels` passed on the Linux workspace.
- 2026-06-18: Windows test binaries for `.`, `./containers`,
  `./etwtracer`, `./logs`, `./node`, `./proc`, `./profiling`, and
  `./tools/metriclabels` compiled on Linux and passed on the Horde
  Windows 11 VM.
- 2026-06-18: The PowerShell install/uninstall scripts passed a live
  service lifecycle smoke on the Horde Windows VM. The service
  `coroot-node-agent-hardening` was installed with
  `--listen=127.0.0.1:18088 --wal-dir=C:\Temp\CorootHardeningData\wal --min-container-age=0s`,
  scraped successfully, and uninstalled. The scrape emitted
  `node_agent_info{machine_id="422bdee8088a455997e3f311384a843e",system_uuid="",version="unknown"} 1`.

## Acceptance Criteria

- [ ] **HARDEN-CRIT-1:** Windows Server 2022 service, node metrics,
      Docker discovery, Docker JSON logs, and process-isolated TCP
      metrics are validated on a provided Server 2022 host.
- [x] **HARDEN-CRIT-2:** `docs/windows-support-matrix.md` records the
      supported and deferred Windows OS/runtime/isolation matrix.
- [x] **HARDEN-CRIT-3:** A metric label compatibility tool can compare
      Linux and Windows scrape files and fail on mismatched label keys
      for metric families emitted by both sides.
- [x] **HARDEN-CRIT-4:** Windows service install/uninstall scripts pass
      syntax validation and a live Windows VM service lifecycle smoke.
- [x] **HARDEN-CRIT-5:** Windows `proc.ListPids` and `proc.GetCmdline`
      have Windows-specific unit coverage.
- [x] **HARDEN-CRIT-6:** CI includes GitHub-hosted Windows compile/unit
      coverage and a self-hosted Windows integration workflow template.
- [x] **HARDEN-CRIT-7:** `make lint`, `make test`, and
      `make crossbuild-check` pass after the hardening changes.
