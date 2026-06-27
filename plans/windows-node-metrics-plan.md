# Windows Node Metrics Plan

**Status:** Complete
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
| `node_info{hostname,kernel_version}` | `os.Hostname()` plus `RtlGetVersion` | Keep label keys unchanged. `kernel_version` is prefixed with `Windows ` on Windows so Coroot classifies the node OS correctly; Coroot strips that prefix from the displayed version. |
| `node_cloud_info{...}` | Existing cloud metadata HTTP paths plus explicit flags | Linux `/sys` DMI probes are omitted on Windows. Empty labels are acceptable when metadata is unavailable. |
| `node_uptime_seconds` | `GetTickCount64` via `windows.DurationSinceBoot` | Must be seconds since boot. |
| `node_resources_cpu_usage_seconds_total{mode}` | `GetSystemTimes` | Must be monotonically increasing seconds. Emit Linux-compatible modes when meaningful; document any modes that are always zero on Windows. |
| `node_resources_cpu_logical_cores` | `runtime.NumCPU()` | Must match logical processor count visible to the process. |
| `node_resources_memory_total_bytes` | `GlobalMemoryStatusEx` | Physical memory total. |
| `node_resources_memory_free_bytes` | `GlobalMemoryStatusEx` | Free physical memory. |
| `node_resources_memory_available_bytes` | `GlobalMemoryStatusEx` | Available physical memory. |
| `node_resources_memory_cached_bytes` | Performance counters or documented zero/omission | Must not fake Linux page-cache semantics. |
| `node_resources_disk_*{device}` | `IOCTL_DISK_PERFORMANCE` for `\\.\PhysicalDriveN` | Device label is `PhysicalDriveN`, stable across scrapes. Counters are omitted when Windows denies or does not support the storage performance query. |
| `node_net_*{interface}` | IP Helper API (`GetAdaptersAddresses` plus `GetIfEntry2Ex`) | Interface label uses the Windows friendly name. |
| `node_net_interface_up{interface}` | IP Helper adapter operational status | 1 for up, 0 for down. |
| `node_net_interface_ip{interface,ip}` | `GetAdaptersAddresses` | Exclude link-local and multicast addresses, matching Linux behavior. |

GPU metrics are not required for M1. The M0 Windows GPU no-op collector
may remain until a later GPU-specific plan.

## Windows Semantic Notes

- CPU `user`, `system`, and `idle` are cumulative seconds from
  `GetSystemTimes`. Windows has no direct Linux-equivalent source for
  `nice`, `iowait`, `irq`, `softirq`, or `steal`, so those modes are
  emitted as zero by the shared collector because the Windows
  `CpuUsage` fields remain unset.
- Memory `total`, `free`, and `available` come from
  `GlobalMemoryStatusEx`. Windows does not expose Linux page-cache
  semantics through this API, so `node_resources_memory_cached_bytes`
  is emitted as zero rather than mapped to an unrelated standby-cache
  value.
- Disk I/O counters use `IOCTL_DISK_PERFORMANCE`, which returns
  cumulative counts and time counters for physical drives. The Windows
  implementation does not synthesize zero-valued disks if the host
  denies physical-drive access or the storage stack does not support
  this query; in that case disk metrics are absent and the rest of the
  node collector continues.
- Network byte and packet counters are cumulative IP Helper interface
  counters. The interface label uses the friendly name exposed by
  Windows, and assigned IP metrics exclude loopback, unspecified,
  link-local, and multicast addresses.

## Linux-vs-Windows Metric Comparison

| Metric family | Linux implementation | Windows implementation | Label compatibility |
|---------------|----------------------|------------------------|--------------------|
| `node_info` | `uname` | `os.Hostname()` and `RtlGetVersion` | Same `hostname`, `kernel_version` labels. |
| `node_cloud_info` | Metadata HTTP plus Linux DMI fallbacks | Metadata HTTP plus explicit flags | Same labels; unavailable metadata remains empty. |
| `node_uptime_seconds` | `/proc/uptime` | `windows.DurationSinceBoot` | No labels. |
| `node_resources_cpu_usage_seconds_total` | `/proc/stat` | `GetSystemTimes` | Same `mode` label; Linux-only modes are zero on Windows. |
| `node_resources_cpu_logical_cores` | `/proc/stat` CPU lines | `runtime.NumCPU()` | No labels. |
| `node_resources_memory_*` | `/proc/meminfo` | `GlobalMemoryStatusEx` | No labels; cached memory is zero on Windows. |
| `node_resources_disk_*` | `/proc/diskstats` block devices | `IOCTL_DISK_PERFORMANCE` physical drives | Same `device` label key; values use Windows physical-drive names. |
| `node_net_*` | netlink link stats | IP Helper interface stats | Same `interface` label key; values use Windows friendly names. |
| `node_net_interface_ip` | netlink addresses | `GetAdaptersAddresses` unicast addresses | Same `interface`, `ip` labels. |

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

## Verification Results

- 2026-06-16: `make lint`, `make crossbuild-check`, and `make test`
  passed on the Linux host after implementation.
- 2026-06-16: Windows test binaries for `./node` and the root package
  were compiled on Linux, copied to the Windows 11 VM
  `coroot-win-gpu-buildtest-20260616-0308` (`10.0.26100`), and passed
  on the VM.
- 2026-06-16: The Windows binary was run on the Windows 11 VM with
  `--listen=127.0.0.1:10300 --disable-pinger --disable-l7-tracing
  --disable-gpu-monitoring`. Two scrapes 16 seconds apart exposed all
  required M1 `node_*` metric families, returned 115 `node_` samples,
  and showed no counter decreases.

## Acceptance Criteria

- [x] **M1-CRIT-1:** `make crossbuild-check` and `make test` pass
      after the Windows node implementation lands.
- [x] **M1-CRIT-2:** A Windows 11 foreground run exposes `/metrics`
      without requiring container runtime or tracing support.
- [x] **M1-CRIT-3:** Required `node_*` metrics from the source map are
      present in a Windows scrape.
- [x] **M1-CRIT-4:** A documented Linux-vs-Windows metric comparison
      confirms names and label keys match for emitted metrics.
- [x] **M1-CRIT-5:** Any unavailable Windows semantic, such as Linux
      page-cache or CPU steal time, is documented instead of being
      misrepresented.
