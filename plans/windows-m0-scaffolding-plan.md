# Windows M0 Scaffolding Plan

**Status:** Complete (2026-06-16)
**Parent:** `plans/windows-port-plan.md` M0
**Created:** 2026-06-16

## Goal

Make the repository compile for both `GOOS=linux` and `GOOS=windows`
without changing Linux runtime behavior. M0 is compile scaffolding only:
Windows collectors may be no-op, but the Windows binary must start far
enough for M1 to implement `/metrics`.

No Windows VM is required for M0. The hard gate is cross-compilation
from a normal development host.

## Rules

- Existing Linux source bodies stay unchanged. Allowed Linux-side edits
  are adding `//go:build linux`, renaming files to `_linux.go`, and
  moving compile-blocking Linux helpers out of shared files without
  changing their bodies.
- No `runtime.GOOS == "windows"` branching in shared files.
- Startup-path Windows stubs must initialize successfully. A no-op
  collector is acceptable; a startup error is not.
- Non-startup Windows APIs may return an explicit "not implemented on
  Windows" error during M0.

## Startup Path That Must Not Error On Windows

`main.go` reaches `/metrics` only after the following calls. M0 stubs
must let all of them complete without a fatal error:

- `uname()`
- `common.SetKernelVersion(...)` or a platform-specific no-op gate
- `whitelistNodeExternalNetworks()`
- `machineID()`
- `systemUUID()`
- `tracing.Init(...)`
- `logs.Init(...)`
- `node.NewCollector(...)`
- `gpu.NewCollector()`
- `profiling.Init(...)`
- `containers.NewRegistry(...)`
- `profiling.Start()`
- `prom.StartAgent(...)`

M1 may improve the values returned by these calls. M0 only requires
that they compile and do not prevent process startup.

## File Inventory

This inventory is the initial M0 checklist. If implementation discovers
another Linux-only file, update this list in the same change.

### Root

- `main.go`: move Linux-only `uname()`, `machineID()`, `systemUUID()`,
  and the Linux kernel-version gate into Linux-only sibling files.
  Keep shared orchestration in `main.go`. Add Windows sibling helpers
  that compile and return non-empty best-effort hostname/machine ID
  values where practical.
- `Makefile`: add `build-linux`, `build-windows`, and
  `crossbuild-check`. Use these targets after they exist.

### Linux-Only Packages Or Files

- `ebpftracer/`: gate the Linux eBPF implementation. The pure L7 parser
  subpackage may remain portable temporarily if shared packages still
  import it; M3 decides whether to move it behind a neutral package.
- `profiling/profiling.go`, `profiling/goheap.go`: gate Linux eBPF and
  `/proc` profiling; add Windows no-op `Init`, `Start`, and `Stop`.
- `pinger/pinger.go`: gate Linux netns/raw-socket implementation; add
  Windows no-op or explicit non-startup error stub.
- `logs/journald_reader.go`: gate journald reader; Windows Event Log is
  M4, not M0.
- `containers/cilium.go`, `containers/crio.go`,
  `containers/journald.go`, `containers/systemd.go`,
  `containers/taskstats.go`: gate Linux-only sources.
- `containers/registry.go`, `containers/container.go`,
  `containers/process.go`: gate the current Linux implementation if
  needed to remove concrete `ebpftracer`, `netns`, `taskstats`, and
  `/proc` dependencies from Windows builds. Add M0 Windows registry
  stubs exposing only the API needed by `main.go` and profiling stubs.
- `proc/*.go`: treat `/proc` and namespace readers as Linux-only unless
  a file is proven portable. Add Windows stubs only for symbols still
  referenced by shared or Windows files.
- `node/cpu.go`, `node/memory.go`, `node/disk.go`, `node/net.go`,
  `node/uptime.go`: gate Linux readers and add Windows siblings. M0
  siblings may return empty metrics; M1 fills real PDH/IP Helper data.
- `node/metadata/`: keep the shared metadata dispatcher compiling on
  Windows; gate Linux providers that require host network namespaces
  and add Windows compile stubs for their provider functions.
- `gpu/gpu.go`: either prove the NVML binding compiles on Windows or
  add a Windows no-op collector for M0. Full GPU support is not part of
  M0.
- `jvm/jattach.go`, `jvm/async_profiler.go`, `jvm/tls.go`: gate any
  `/proc` or Linux attach behavior that remains reachable from Windows
  builds.

### Shared Packages Expected To Stay Portable

- `flags/`
- `common/` except any future OS-version helper split
- `prom/`
- `tracing/` after its `ebpftracer/l7` import is either proven portable
  or moved behind a neutral package
- `logs/tail_reader.go`

## Acceptance Criteria

- [x] **M0-CRIT-1:** `make crossbuild-check` exists and runs
      `GOOS=linux go build ./...` and `GOOS=windows go build ./...`.
- [x] **M0-CRIT-2:** `make crossbuild-check` succeeds from a clean
      checkout on the development host.
- [x] **M0-CRIT-3:** `make test` succeeds on Linux after the file
      splits.
- [x] **M0-CRIT-4:** Windows startup-path stubs for `containers/`,
      `profiling/`, `gpu/`, `logs/`, `tracing/`, and `node/` do not
      return fatal startup errors.
- [x] **M0-CRIT-5:** No Linux implementation body is functionally
      changed. The diff is limited to build tags, renames, moved helper
      bodies, new shared interfaces, new Windows stubs, Makefile
      targets, and documentation.
