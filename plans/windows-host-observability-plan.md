# Windows Host Observability Parity Plan

**Status:** In progress
**Parent:** `plans/windows-port-plan.md` M6
**Created:** 2026-06-25

## Goal

Close the major Windows parity gaps that are not centered on
containers, virtual machines, or Windows Server validation. This plan
turns the remaining host-observability work into independently
shippable milestones with explicit product requirements, acceptance
criteria, and test expectations.

## Non-goals

- Containerd/CRI log discovery on Windows.
- Hyper-V, VM, or guest-level collection.
- Windows Server Kubernetes or HostProcess DaemonSet validation.
- ETW container network fallback work already tracked in
  `plans/windows-network-fallback-plan.md`.
- Replacing Linux eBPF profiling or tracing implementations.

## Milestones

### M6.1 — Windows Event Log ingestion

Product requirements:

- The Windows binary can subscribe to configured Windows Event Log
  channels.
- The agent emits Event Log pattern metrics separately from container
  stdout/stderr metrics so operators can distinguish host/service
  events from container logs.
- The agent forwards parsed Event Log patterns to the existing OTLP logs
  exporter when `--logs-endpoint` is configured.
- Event Log ingestion can be disabled independently from container log
  parsing.

Acceptance criteria:

- [x] **EVT-CRIT-1:** `GOOS=windows go test ./logs` exercises the Event
      Log collector label contract without importing Linux-only log
      sources.
- [x] **EVT-CRIT-2:** `make lint`, `make test`, and
      `make crossbuild-check` pass.
- [x] **EVT-CRIT-3:** A Windows run with default settings subscribes to
      `Application` and `System`, and `/metrics` can expose
      `windows_event_log_messages_total`.
- [x] **EVT-CRIT-4:** `--disable-windows-event-log-monitoring` disables
      Event Log collection while leaving Docker JSON log parsing
      unchanged.
- [x] **EVT-CRIT-5:** User docs list the Event Log flags, default
      channels, metric name, and required permissions.

Testing requirements:

- Unit tests cover the metric labels and collector state transitions
  with synthetic entries.
- Cross-build must prove Linux builds do not include Windows Event Log
  APIs.
- A Windows smoke test must write or locate a recent Application/System
  event and verify the metric appears.

Verification log:

- 2026-06-25: `make lint`, `make test`, and `make crossbuild-check`
  passed on the Linux workspace.
- 2026-06-25: On Windows 11 VM
  `coroot-win-gpu-buildtest-20260616-0308`, `go test ./logs` passed.
- 2026-06-25: On the same Windows VM, the built agent ran with
  `--listen=127.0.0.1:18092` and default Event Log settings. It
  subscribed to `[Application System]`, `eventcreate` wrote an
  Application error from provider `CorootEventLogSmoke` with event ID
  `778`, and `/metrics` emitted
  `windows_event_log_messages_total{channel="Application",event_id="778",level="error",provider="CorootEventLogSmoke",sample="ERROR coroot event log smoke 20260625 second",...} 1`.

### M6.2 — Windows OTLP trace export

Product requirements:

- The Windows binary honors `--traces-endpoint` and
  `--traces-sampling`.
- Windows trace export uses the same TLS and API-key configuration
  surfaces as existing OTLP metrics and logs.
- The first Windows trace source is agent lifecycle spans, giving
  operators a working end-to-end trace export path without promising
  Linux L7 parity.

Acceptance criteria:

- [x] **TRACE-CRIT-1:** `GOOS=windows go test ./tracing` validates
      Windows sampling configuration and disabled-endpoint behavior.
- [x] **TRACE-CRIT-2:** `make lint`, `make test`, and
      `make crossbuild-check` pass.
- [x] **TRACE-CRIT-3:** When `--traces-endpoint` is unset, Windows trace
      setup is a no-op and startup continues.
- [x] **TRACE-CRIT-4:** When `--traces-endpoint` is set, the Windows
      binary initializes an OTLP trace provider with the configured
      sampling ratio and emits at least one lifecycle span.
- [x] **TRACE-CRIT-5:** User docs describe Windows trace export as
      lifecycle-only and do not imply L7 tracing parity.

Testing requirements:

- Unit tests cover invalid sampling values, disabled endpoints, and the
  provider initialization path.
- Cross-build confirms Linux tracing remains Linux-tagged and unchanged.
- A local OTLP test receiver or mocked exporter validates lifecycle span
  emission on Windows.

Verification log:

- 2026-06-25: `make lint`, `make test`, and `make crossbuild-check`
  passed on the Linux workspace.
- 2026-06-25: On Windows 11 VM
  `coroot-win-gpu-buildtest-20260616-0308`, `go test ./tracing`
  passed. The Windows test suite covered nil-endpoint no-op behavior,
  sampling normalization, and lifecycle span delivery to an
  `httptest` OTLP HTTP receiver.

### M6.3 — Windows profiling MVP

Product requirements:

- Windows exposes an explicit, documented profiling mode instead of a
  silent no-op.
- The first supported mode is agent self CPU profiling, uploaded to the
  configured profiles endpoint with host identity labels.
- Profiling remains disabled by default until a profile endpoint and
  supported mode are configured.
- Unsupported process/container profiling remains clearly documented as
  deferred.

Acceptance criteria:

- [ ] **PROF-CRIT-1:** `GOOS=windows go test ./profiling` validates the
      disabled/default state and request-building behavior.
- [ ] **PROF-CRIT-2:** `make lint`, `make test`, and
      `make crossbuild-check` pass.
- [ ] **PROF-CRIT-3:** With `--profiles-endpoint` and
      `--windows-profile=agent-cpu`, the Windows binary periodically
      uploads Go CPU pprof payloads for the agent process.
- [ ] **PROF-CRIT-4:** With default settings, Windows profiling starts no
      goroutines and sends no profile uploads.
- [ ] **PROF-CRIT-5:** Docs identify the MVP as agent self profiling and
      keep host/container process profiling listed as future work.

Testing requirements:

- Unit tests cover endpoint/mode validation and upload request metadata.
- A Windows smoke test runs with a short interval and verifies an upload
  reaches a test HTTP endpoint.
- Cross-build confirms Linux profiling behavior is not changed.

### M6.4 — Rich Windows cloud metadata

Product requirements:

- Windows metadata collection returns the same rich AWS, GCP, and IBM
  labels that Linux already reports when the provider metadata service is
  reachable.
- Detection remains based on Windows SMBIOS/firmware hints where
  available, but metadata enrichment uses provider APIs.
- Provider metadata failures remain best-effort and do not block agent
  startup.

Acceptance criteria:

- [ ] **META-CRIT-1:** `GOOS=windows go test ./node/metadata` covers
      AWS, GCP, and IBM parsing/enrichment helpers.
- [ ] **META-CRIT-2:** `make lint`, `make test`, and
      `make crossbuild-check` pass.
- [ ] **META-CRIT-3:** Windows AWS metadata includes at least region,
      availability zone, instance type, lifecycle, account ID, and
      instance profile where available.
- [ ] **META-CRIT-4:** Windows GCP metadata includes at least region,
      availability zone, instance type, preemptible status, account ID,
      and project name where available.
- [ ] **META-CRIT-5:** Windows IBM metadata includes at least region,
      availability zone, instance type, lifecycle, and account ID where
      available.

Testing requirements:

- Unit tests use deterministic provider payloads and do not call live
  metadata services.
- Cross-build proves Linux metadata files remain Linux-only.
- Optional Windows VM validation can force provider flags and verify
  labels if cloud metadata endpoints are reachable.

### M6.5 — Windows CLI/config parity

Product requirements:

- Windows exposes only the flags it can honor.
- Windows supports OTLP trace/profile endpoint defaults derived from the
  collector endpoint, matching the existing metric/log endpoint pattern.
- New Windows-only flags have environment-variable equivalents using the
  `COROOT_` prefix.
- Unsupported Linux-only flags remain absent from the Windows help text.

Acceptance criteria:

- [ ] **CLI-CRIT-1:** `GOOS=windows go test ./flags` covers Windows
      collector endpoint derivation and Windows-only flag defaults.
- [ ] **CLI-CRIT-2:** `make lint`, `make test`, and
      `make crossbuild-check` pass.
- [ ] **CLI-CRIT-3:** Windows help includes Event Log, trace endpoint,
      profile endpoint, and Windows profile flags.
- [ ] **CLI-CRIT-4:** Windows help does not expose Linux-only eBPF,
      cgroup, pinger, or Java async-profiler flags.
- [ ] **CLI-CRIT-5:** Docs list the Windows-supported flag set and
      identify Linux-only exclusions.

Testing requirements:

- Unit tests validate derived endpoint behavior.
- A Windows help snapshot or smoke command verifies visible flags.
- Cross-build confirms Linux flag behavior remains unchanged.

### M6.6 — Windows release signing and checksums

Product requirements:

- Windows release assets include SHA-256 checksum files.
- Release CI signs the Windows `.exe` and `.msi` when Authenticode
  signing secrets are configured.
- Signing is conditional so forks without certificates still produce
  release artifacts, but docs clearly mark unsigned fallback behavior.
- Release docs explain required secrets and verification commands.

Acceptance criteria:

- [ ] **REL-CRIT-1:** Release workflow generates SHA-256 checksum
      artifacts for Windows `.exe` and `.msi` assets.
- [ ] **REL-CRIT-2:** Release workflow signs Windows artifacts when
      signing certificate secrets are present and verifies the signature
      before upload.
- [ ] **REL-CRIT-3:** Release workflow still succeeds without signing
      secrets and documents the unsigned fallback.
- [ ] **REL-CRIT-4:** `make lint`, `make test`, and
      `make crossbuild-check` pass.
- [ ] **REL-CRIT-5:** User docs explain checksum verification,
      Authenticode verification, and release signing secrets.

Testing requirements:

- Static validation parses workflow and PowerShell signing scripts.
- A dry run without signing secrets validates checksum generation.
- A signed validation run requires a real certificate or a Windows test
  certificate and must record verification output in this plan.

## Overall Acceptance Criteria

- [ ] **HOSTOBS-CRIT-1:** All M6.1-M6.6 milestone criteria are checked.
- [ ] **HOSTOBS-CRIT-2:** `make lint`, `make test`, and
      `make crossbuild-check` pass after the final milestone.
- [ ] **HOSTOBS-CRIT-3:** `docs/windows-support-matrix.md` no longer
      lists Event Log ingestion, Windows trace export, agent self
      profiling, AWS/GCP/IBM metadata enrichment, Windows CLI parity, or
      Windows release checksums/signing as missing without the documented
      caveats from this plan.
