# Windows Support Matrix

Windows support on this branch is implementation-complete for the M0-M5
milestones, but final support validation still requires a Windows Server
2022 host.

## Operating Systems

| OS | Status | Notes |
|----|--------|-------|
| Windows 11 Enterprise 10.0.26100 | Development validated | Validated on the Horde VM for service lifecycle, node metrics, Docker discovery, Docker JSON logs, and process-isolated TCP metrics. |
| Windows Server 2022 | Required before supported release | Blocked until a Server 2022 host is available. Repeat the Windows quickstart service smoke plus container/log/TCP smokes there before marking Windows supported. |
| Windows Server 2019 | Not claimed | Needs explicit validation of PDH, ETW, Docker/HCS/HNS behavior, and service install before support can be claimed. |
| Windows Server 2025 | Not claimed | Needs explicit validation before support can be claimed. |

## Container Runtimes

| Runtime | Status | Notes |
|---------|--------|-------|
| Docker Engine, Windows containers | Validated on Windows 11 | Docker API source supports `container_info`, restarts, Docker JSON logs, and process-isolated TCP attribution. |
| Docker Desktop Linux/WSL engine | Unsupported | Rejected because it exposes Linux containers rather than Windows host containers. |
| containerd / CRI on Windows | Deferred | Needs a host with Windows containerd/CRI before implementation and validation. |
| HCS/HNS direct source | Deferred | Reserved for runtime gaps and network fallback work. |

## Isolation Modes

| Isolation mode | Status | Notes |
|----------------|--------|-------|
| Process-isolated Docker containers | Validated on Windows 11 | Required for PID-attributed ETW TCP metrics. |
| Hyper-V isolated Docker containers | Partial | Container discovery works, but ETW network PIDs did not match container identity in M3 validation. TCP attribution is not claimed. |

## Metric Support

| Area | Windows status |
|------|----------------|
| Startup and `node_*` metrics | Implemented and Windows 11 validated. |
| `container_info` and restarts | Implemented for Docker Windows containers. |
| Docker stdout/stderr log patterns | Implemented for Docker `json-file` log driver. |
| TCP connect/bytes/active metrics | Implemented for process-isolated Docker containers where ETW data events carry host PIDs. |
| DNS, failed connect, listen metrics | Deferred to `plans/windows-network-fallback-plan.md`. |
| Profiling | Not supported on Windows yet; the Windows package is an explicit no-op. Tracked in `plans/windows-profiling-plan.md`. |

## Final Support Gate

Before README and CONTRIBUTING call Windows generally supported:

1. Run `make lint`, `make test`, and `make crossbuild-check`.
2. Run the documented service lifecycle smoke on Windows Server 2022.
3. Run Docker discovery, Docker JSON log, and process-isolated TCP
   smokes on Windows Server 2022.
4. Capture Linux and Windows `/metrics` scrapes for equivalent
   workloads and compare common metric label keys with
   `go run ./tools/metriclabels`.
