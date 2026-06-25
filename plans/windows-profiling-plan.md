# Windows Profiling Plan

**Status:** Agent self profiling MVP complete; process/container profiling future work
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

The Windows package now supports an explicit MVP mode:

- `--windows-profile=agent-cpu` collects a Go CPU pprof for the
  `coroot-node-agent.exe` process itself.
- `--profiles-endpoint` configures upload; `--collector-endpoint`
  derives `/v1/profiles` when the profile endpoint is omitted.
- Uploads use host identity labels plus `service.name=coroot-node-agent`,
  `profile.type=cpu`, and `profile.target=agent`.
- No process-info channel is consumed because this MVP does not profile
  host or container workloads.
- A profiling update channel is still returned so container registry
  wiring stays non-blocking.

Host process profiling and container profiling remain future work and
must not be implied by the MVP.

## MVP Acceptance Criteria

- [x] **PROF-MVP-CRIT-1:** Windows profiling is disabled by default when
      no profiles endpoint or no supported Windows profile mode is set.
- [x] **PROF-MVP-CRIT-2:** `--windows-profile=agent-cpu` uploads a Go
      CPU pprof for the agent process to `--profiles-endpoint`.
- [x] **PROF-MVP-CRIT-3:** Upload requests include host identity labels,
      `service.name=coroot-node-agent`, `profile.type=cpu`, and
      `profile.target=agent`.
- [x] **PROF-MVP-CRIT-4:** `make lint`, `make test`, and
      `make crossbuild-check` pass.
- [x] **PROF-MVP-CRIT-5:** `GOOS=windows go test ./profiling` passes on
      a Windows validation host.

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
