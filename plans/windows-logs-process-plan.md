# Windows Logs and Process Detail Plan

**Status:** Complete
**Parent:** `plans/windows-port-plan.md` M4
**Created:** 2026-06-17

## Goal

Emit Windows container log-pattern metrics for supported runtime log
sources while preserving the existing Linux log implementation.

M4 starts with Docker's `json-file` stdout/stderr log path because it
uses the same on-disk format and parser already used on Linux. Windows
Event Log is a separate source with different identity and lifecycle
semantics, so it is deferred until a future source-specific plan.

## Supported Scope

Implemented in this slice:

- Docker Engine API inspection captures `LogPath` for Windows
  containers whose log driver is `json-file`.
- A Windows-only log parser manager starts one Docker JSON parser per
  reportable container, tails the host log path from the current end,
  and stops the parser when the container disappears or the log path
  changes.
- Windows emits `container_log_messages_total` with the same metric name
  and label keys as Linux, wrapped with the Windows registry's
  `container_id` and `app_id` labels.
- `--disable-log-parsing`, `--log-patterns-per-container`, and
  `--max-label-length` apply to Windows Docker log parsing.

Deferred beyond this slice:

- Windows Event Log ingestion and source attribution.
- Containerd/CRI log files on Windows, pending a validated Windows
  containerd/CRI runtime.
- File-log discovery inside Windows containers. There is no Windows
  `/var/log` convention equivalent in the current milestone.
- Windows profiling remains the existing no-op stub; profiling support
  needs its own plan.

Implemented during support hardening:

- Windows `proc.ListPids` now enumerates host process IDs with
  `CreateToolhelp32Snapshot`.
- Windows `proc.GetCmdline` now returns the process image path via
  `QueryFullProcessImageName` as a best-effort command-line analogue.
  Full argument capture remains deferred until a safe PEB/WMI strategy
  is chosen.

## Metric Semantics

`container_log_messages_total` keeps the Linux label contract:

- `container_id`
- `app_id`
- `source`
- `level`
- `pattern_hash`
- `sample`

For Docker JSON logs on Windows, `source` is `stdout/stderr`, matching
the Linux Docker JSON source.

The tail reader starts at the end of the current Docker log file. This
matches the existing Linux behavior and avoids replaying historical log
content when the agent starts.

## Verification Procedure

On a Windows 11 host with a Windows Docker Engine:

1. Start a Windows container using Docker's `json-file` log driver that
   continues writing stdout after the agent has started.
2. Run the Windows agent with `DOCKER_HOST=npipe:////./pipe/docker_engine`,
   `--min-container-age=0s`, and a writable `--wal-dir`.
3. Scrape `/metrics` until `container_log_messages_total` appears for
   the container's logical `container_id`.
4. Verify the sample carries `source="stdout/stderr"` and the expected
   `container_id` / `app_id` label set.

## Verification Log

- 2026-06-17: `make test` and `make crossbuild-check` passed on the
  Linux workspace.
- 2026-06-17: Windows-only test binaries
  `coroot-containers.test.exe` and `coroot-logs.test.exe` passed on the
  Horde Windows VM. The container test includes a Docker JSON log parser
  smoke that tails a temp file and emits
  `container_log_messages_total`; the logs test verifies the portable
  append/partial-line tail-reader behavior on Windows.
- 2026-06-17: Live M4 smoke passed on the Horde Windows VM with Docker
  Engine `windows/29.5.3`. A process-isolated
  `mcr.microsoft.com/windows/nanoserver:ltsc2025` container named
  `coroot-m4-log` used Docker `json-file` logging with log path
  `C:\ProgramData\docker\containers\60b7a3de81b2ea48c904bc9956dd2e802335c25a7f69125a53cbd4a5c4a65eae\60b7a3de81b2ea48c904bc9956dd2e802335c25a7f69125a53cbd4a5c4a65eae-json.log`.
  The agent ran with `--listen=127.0.0.1:18086`,
  `--min-container-age=0s`, and `--wal-dir=C:\Temp\coroot-m4-wal`.
  Scraping `/metrics` emitted:
  `container_log_messages_total{app_id="",container_id="/docker/coroot-m4-log",level="error",pattern_hash="752e08f11bb2d256c5104d562beaa266",sample="ERROR coroot m4 log line 3",source="stdout/stderr"} 2`
  plus host-level const labels.

## Acceptance Criteria

- [x] **M4-CRIT-1:** `make crossbuild-check` and `make test` pass.
- [x] **M4-CRIT-2:** Windows builds emit
      `container_log_messages_total` without importing Linux-only
      container, journald, or cgroup code.
- [x] **M4-CRIT-3:** Windows Docker inspection records `LogPath` only
      for the supported `json-file` log driver.
- [x] **M4-CRIT-4:** Windows unit coverage proves a Docker JSON log
      entry is parsed into a `container_log_messages_total` sample with
      Linux-compatible label keys.
- [x] **M4-CRIT-5:** A live Windows VM smoke test proves a
      containerized app writing to stdout produces
      `container_log_messages_total` for the correct logical
      `container_id`.
- [x] **M4-CRIT-6:** Deferred Windows Event Log, containerd/CRI logs,
      file-log discovery, and profiling work are documented rather than
      silently approximated.
