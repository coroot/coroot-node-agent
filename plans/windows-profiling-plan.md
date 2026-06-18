# Windows Profiling Plan

**Status:** Accepted for future work
**Parent:** `plans/windows-port-plan.md` profiling future work
**Created:** 2026-06-18

## Goal

Define the work required before Windows profiling can replace the
current explicit no-op implementation.

Linux profiling depends on eBPF, `/proc/<pid>/mem`, ELF symbol lookup,
perf maps, and Linux JVM attach paths. Those mechanisms do not carry
over to Windows. Windows must not emit Linux profiling metrics with
weaker semantics.

## Candidate Sources

1. **ETW CPU sampling.** Candidate providers include Windows kernel CPU
   profiling events. The design must prove sample attribution to the
   same logical `container_id` used by the Windows container registry.
2. **Windows Performance Recorder / TraceLogging pipeline.** Consider
   only if collection can run continuously with acceptable overhead and
   permissions.
3. **Runtime-specific profilers.** Go `net/http/pprof`, .NET EventPipe,
   and JVM tooling may be useful, but each needs a container/process
   discovery contract and upload semantics before implementation.

## Current Implementation

`profiling/profiling_windows.go` remains an explicit no-op:

- no process-info channel is consumed;
- a profiling update channel is still returned so container registry
  wiring stays non-blocking;
- `Start` and `Stop` are no-ops.

## Acceptance Criteria

- [ ] **PROF-CRIT-1:** A Windows profiling source is selected with
      documented provider/API names, required privileges, sample fields,
      and overhead expectations.
- [ ] **PROF-CRIT-2:** Samples are attributed to the correct logical
      `container_id` for a process-isolated Windows Docker container.
- [ ] **PROF-CRIT-3:** Profile upload payloads are compatible with the
      existing Coroot profile ingestion semantics, or differences are
      documented as Windows-specific.
- [ ] **PROF-CRIT-4:** `make lint`, `make test`, and
      `make crossbuild-check` pass after implementation.
