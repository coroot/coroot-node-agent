# Windows Node Metrics Plan

**Status:** Draft
**Parent:** `plans/windows-port-plan.md` M1
**Created:** 2026-06-16

## Goal

Implement real Windows `node_*` metrics while preserving the existing
Linux metric names and label keys. M1 assumes M0 already cross-builds
and starts with no-op Windows collectors.

M1 requires a Windows 11 VM for development runtime verification.
Before Windows support is marked final, repeat the same smoke test on
Windows Server 2022 unless the support matrix is explicitly changed.

## Source Map

Required M1 metrics:

| Metric | Windows source | Notes |
|--------|----------------|-------|
| `node_info{hostname,kernel_version}` | `os.Hostname()` plus Windows version API | Keep label keys unchanged. `kernel_version` carries Windows build/version text on Windows. |
| `node_cloud_info{...}` | Existing cloud metadata HTTP paths plus explicit flags | Linux `/sys` DMI probes are omitted on Windows. Empty labels are acceptable when metadata is unavailable. |
| `node_uptime_seconds` | `GetTickCount64` or equivalent monotonic boot-time API | Must be seconds since boot. |
| `node_resources_cpu_usage_seconds_total{mode}` | Windows cumulative processor time API, preferably raw system processor performance counters | Must be monotonically increasing seconds. Emit Linux-compatible modes when meaningful; document any modes that are always zero on Windows. |
| `node_resources_cpu_logical_cores` | `runtime.NumCPU()` or Windows processor topology API | Must match logical processor count visible to the process. |
| `node_resources_memory_total_bytes` | `GlobalMemoryStatusEx` or equivalent | Physical memory total. |
| `node_resources_memory_free_bytes` | `GlobalMemoryStatusEx` | Free physical memory. |
| `node_resources_memory_available_bytes` | `GlobalMemoryStatusEx` | Available physical memory. |
| `node_resources_memory_cached_bytes` | Performance counters or documented zero/omission | Must not fake Linux page-cache semantics. |
| `node_resources_disk_*{device}` | PDH `PhysicalDisk` counters or Windows storage performance APIs | Device label should be stable across scrapes. |
| `node_net_*{interface}` | IP Helper API (`GetIfTable2`/adapter stats) or PDH network-interface counters | Interface label should be stable and human-recognizable. |
| `node_net_interface_up{interface}` | IP Helper adapter operational status | 1 for up, 0 for down. |
| `node_net_interface_ip{interface,ip}` | `GetAdaptersAddresses` | Exclude link-local and multicast addresses, matching Linux behavior. |

GPU metrics are not required for M1. The M0 Windows GPU no-op collector
may remain until a later GPU-specific plan.

## Verification Procedure

On a Windows 11 VM:

1. Build the Windows binary from the branch under test.
2. Run it as a foreground process with a non-privileged metrics port,
   for example `--listen=127.0.0.1:10300`.
3. Scrape `http://127.0.0.1:10300/metrics`.
4. Verify all required metric names above are present, with the same
   label keys as Linux.
5. Scrape twice at least 15 seconds apart and verify counter metrics
   do not decrease.

## Acceptance Criteria

- [ ] **M1-CRIT-1:** `make crossbuild-check` and `make test` pass
      after the Windows node implementation lands.
- [ ] **M1-CRIT-2:** A Windows 11 foreground run exposes `/metrics`
      without requiring container runtime or tracing support.
- [ ] **M1-CRIT-3:** Required `node_*` metrics from the source map are
      present in a Windows scrape.
- [ ] **M1-CRIT-4:** A documented Linux-vs-Windows metric comparison
      confirms names and label keys match for emitted metrics.
- [ ] **M1-CRIT-5:** Any unavailable Windows semantic, such as Linux
      page-cache or CPU steal time, is documented instead of being
      misrepresented.
