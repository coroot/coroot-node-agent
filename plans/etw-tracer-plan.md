# ETW Tracer Plan

**Status:** Draft
**Parent:** `plans/windows-port-plan.md` M3
**Created:** 2026-06-16

## Goal

Implement Windows container tracing with ETW as the required backend.
The Windows implementation must not import Linux-only `ebpftracer`
types into Windows builds.

M3 requires a Windows 11 VM with administrator permissions needed to
start ETW sessions and run supported Windows containers. Before Windows
support is marked final, repeat the M3 smoke test on Windows Server
2022 unless the support matrix is explicitly changed.

## Package Boundary

M3 introduces a platform-neutral event contract consumed by the
container layer. The implementation may be a new package such as
`tracerapi/` or `containerevents/`; choose the final name during M0/M3
implementation and update this plan.

The contract must cover:

- process start
- process exit
- listen open
- listen close
- connection open
- connection error
- connection close
- DNS request
- file open events needed by log discovery
- optional OOM-equivalent reason, only if a precise Windows source is
  found

Linux adapters may wrap existing `ebpftracer` events. Windows adapters
normalize ETW payloads into the same contract. Shared Windows code must
not depend on concrete `ebpftracer.Tracer`, `ebpftracer.Event`, or
`ebpftracer/l7` imports unless that subpackage is explicitly declared
portable or moved.

## ETW Source Map

The first implementation pass must fill this table with exact provider
names, event IDs, payload fields, and privilege requirements before M3
is marked complete.

| Internal event or metric | Candidate Windows source | Required fields |
|--------------------------|--------------------------|-----------------|
| Process start/exit | Kernel process ETW provider | PID, parent PID if available, image path, command line if available, timestamp, exit reason if available |
| TCP connect success/failure | TCP/IP ETW provider or runtime/HNS correlation | PID or endpoint correlation key, source/destination address, duration or timestamp, status |
| TCP listen open/close | TCP/IP ETW provider plus periodic socket snapshot if needed | PID, listen address, timestamp |
| Active TCP bytes | ETW network events or documented omission | PID/container attribution, bytes sent, bytes received |
| DNS request | DNS Client ETW provider | PID if available, query name, result IPs, status, duration/timestamp |
| File open for logs | Kernel file ETW provider or runtime log metadata | PID/container, path, write/read flags |
| OOM-equivalent | HCS/runtime/container termination status if semantically precise | Container ID, termination reason, timestamp |

If ETW exposes an event but does not provide reliable container
attribution, the metric must be documented as omitted or deferred. Do
not emit Linux metric names with weaker semantics unless the plan
explicitly records the semantic difference.

## M3 Metric Scope

Required if ETW attribution is sufficient:

- `container_net_tcp_successful_connects_total`
- `container_net_tcp_connection_time_seconds_total`
- `container_net_tcp_failed_connects_total`
- `container_net_tcp_active_connections`
- `container_net_tcp_bytes_sent_total`
- `container_net_tcp_bytes_received_total`
- `container_net_tcp_listen_info`
- `container_dns_requests_total`
- `container_dns_requests_duration_seconds_total`
- `ip_to_fqdn`

Optional or conditional:

- `container_net_tcp_retransmits_total`
- `container_oom_kills_total`
- L7 protocol metrics beyond DNS

## Fallback Rule

WFP is not part of M3 unless an ETW acceptance test fails in a way that
blocks a required metric and cannot be solved through runtime/HNS
correlation. If that happens:

1. Record the exact failed ETW test and missing fields here.
2. Create `plans/windows-network-fallback-plan.md`.
3. Do not add driver code until that fallback plan has acceptance
   criteria for signing, installation, upgrade, and runtime safety.

## Verification Procedure

On a Windows 11 host:

1. Run at least one Windows container that opens a TCP listener.
2. Generate successful and failed outbound TCP connections from inside
   a container.
3. Generate DNS lookups from inside a container.
4. Scrape `/metrics` twice.
5. Verify required metrics are emitted with Linux-compatible names and
   label keys.
6. Verify events are attributed to the correct logical container ID
   from M2.

## Acceptance Criteria

- [ ] **M3-CRIT-1:** `make crossbuild-check` and `make test` pass.
- [ ] **M3-CRIT-2:** The ETW source map records exact provider names,
      event IDs, payload fields, and privileges for each implemented
      event.
- [ ] **M3-CRIT-3:** Windows builds do not import Linux-only
      `ebpftracer` packages or types.
- [ ] **M3-CRIT-4:** Required TCP and DNS metrics are emitted on
      Windows with Linux-compatible metric names and label keys, or
      each omission is explicitly documented with the failed ETW proof.
- [ ] **M3-CRIT-5:** Metric samples are attributed to the correct
      logical container ID for the verification workload.
- [ ] **M3-CRIT-6:** Any WFP fallback work is deferred to a separate
      accepted sub-plan.
