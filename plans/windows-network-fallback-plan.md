# Windows Network Fallback Plan

**Status:** Accepted for future work
**Parent:** `plans/etw-tracer-plan.md` M3-B and M3-C
**Created:** 2026-06-17

## Goal

Define the fallback source for Windows container network metrics that
ETW cannot currently prove with reliable container attribution.

This plan exists because the M3 DNS proof failed for process-isolated
Windows Docker containers on the Horde VM. Host DNS Client and Winsock
NameResolution ETW sessions did not emit the container's unique query
with the container process PID. If listen or failed-connect attribution
also fails under ETW, this plan owns that fallback decision too.

## Candidate Sources

1. **HNS runtime metadata and diagnostics.** Prefer an existing
   user-mode API if it exposes container endpoint, DNS proxy, and socket
   state with a stable container key.
2. **WFP callout or event source.** Use only if user-mode HNS/ETW data
   cannot satisfy the metrics. A WFP implementation must have a driver
   signing, installation, upgrade, and rollback story before any driver
   code lands.
3. **Inside-container ETW helper.** Consider only if it can run with
   acceptable privileges and deployment ergonomics for Windows nodes.

## Deferred Metric Surface

- `container_dns_requests_total`
- `container_dns_requests_duration_seconds_total`
- `ip_to_fqdn`
- `container_net_tcp_failed_connects_total`
- `container_net_tcp_listen_info`

## Required Design Constraints

- Do not emit Linux metric names with weaker Windows semantics.
- Every emitted sample must be attributable to the same logical
  `container_id` shape used by M2.
- If a kernel driver is required, the plan must define signing,
  installation, upgrade, and uninstall behavior before implementation.
- The final design must compile under both `GOOS=linux` and
  `GOOS=windows` without importing Windows-only code into Linux builds.

## Acceptance Criteria

- [ ] **FALLBACK-CRIT-1:** A Windows VM proof records the exact fallback
      source, provider/API names, event IDs or API calls, required
      privileges, and payload fields for each recovered metric.
- [ ] **FALLBACK-CRIT-2:** A process-isolated Windows Docker container
      workload proves DNS request attribution to the correct logical
      `container_id` and emits `container_dns_requests_total` and
      `ip_to_fqdn` samples, or DNS remains explicitly omitted.
- [ ] **FALLBACK-CRIT-3:** If WFP is selected, driver signing,
      installation, upgrade, rollback, and uninstall procedures are
      documented and manually verified on a fresh Windows VM before
      driver code is added.
- [ ] **FALLBACK-CRIT-4:** `make lint`, `make test`, and
      `make crossbuild-check` pass after any fallback implementation.
