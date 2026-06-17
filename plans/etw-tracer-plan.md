# ETW Tracer Plan

**Status:** Complete
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

M3 introduces a Windows-only ETW package named `etwtracer/` and a
small event contract consumed by the Windows container layer. Linux
continues to use `ebpftracer/` directly; no Linux implementation body
is refactored for this milestone.

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

Windows adapters normalize ETW payloads into the `etwtracer.Event`
contract. Windows code must not depend on concrete
`ebpftracer.Tracer`, `ebpftracer.Event`, or `ebpftracer/l7` imports
unless that subpackage is explicitly declared portable or moved.

## ETW Source Map

The first implementation pass must fill this table with exact provider
names, event IDs, payload fields, and privilege requirements before M3
is marked complete.

| Internal event or metric | Candidate Windows source | Required fields |
|--------------------------|--------------------------|-----------------|
| Process/container attribution | Docker Engine `ContainerTop` for process-isolated containers | Container ID, logical `container_id`, `app_id`, host PID. Verified on the Horde VM: Docker `top` reports exec workload host PIDs for process-isolated containers. Hyper-V isolated containers expose internal PIDs that did not match ETW network PIDs in the 2026-06-17 smoke; Hyper-V attribution is deferred to HNS/WFP correlation. |
| TCP connect success/failure | `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`), keywords `KERNEL_NETWORK_KEYWORD_IPV4=0x10` and `KERNEL_NETWORK_KEYWORD_IPV6=0x20`, level Informational | Event IDs `12/28` ("Connection attempted"), `13/29` ("Disconnect issued"), `15/31` ("Connection accepted"), `16/32` ("Reconnect attempted"), and data events `10/26` / `11/27`; fields `PID,size,daddr,saddr,dport,sport,startime,endtime,seqnum,connid`. First implementation counts a connection successful once a PID-attributed TCP data event is observed. Failed connect attribution remains pending a failing-workload proof. |
| TCP listen open/close | Deferred to `plans/windows-network-fallback-plan.md` | `Microsoft-Windows-Kernel-Network` did not prove a durable listener-open event with listen address. A process-isolated container listener was visible in Docker `top`, but host `Get-NetTCPConnection`, `netstat -ano`, and the normal TCP owner table did not show the container-compartment listener by PID or port. Do not emit `container_net_tcp_listen_info` on Windows until a fallback source proves container-compartment visibility and attribution. |
| Active TCP bytes | `Microsoft-Windows-Kernel-Network` | Event IDs `10/26` ("Data sent") and `11/27` ("Data received") with `PID,size,daddr,saddr,dport,sport,connid`; PID is joined to Docker `ContainerTop` output. |
| DNS request | Deferred to `plans/windows-network-fallback-plan.md` | `Microsoft-Windows-DNS-Client` (`{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`) exposes useful host fields, but did not emit process-isolated container queries with the container `curl.exe` PID in the Horde VM proof. `Microsoft-Windows-Winsock-NameResolution` also did not emit the container query. Do not emit `container_dns_requests_total`, DNS duration, or `ip_to_fqdn` on Windows until a fallback source proves container attribution. |
| File open for logs | Deferred to M4 | Candidate provider `Microsoft-Windows-Kernel-File` (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`). |
| OOM-equivalent | Deferred | No precise Windows semantic equivalent has been proven. |

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

## Implementation Slices

1. **M3-A: ETW TCP byte/connect scaffold — implemented.** Add `etwtracer/` and
   Windows container-layer integration for process-isolated Docker
   containers. Emit PID-attributed TCP byte counters, active connection
   gauges, and successful connection counters from
   `Microsoft-Windows-Kernel-Network` data events. Document Hyper-V,
   failed-connect, listen, DNS, and OOM gaps in this plan.
2. **M3-B: DNS attribution — deferred.** DNS Client and Winsock
   NameResolution ETW providers did not expose process-isolated
   container DNS queries with a container PID on the Horde VM. DNS
   metrics remain omitted on Windows until
   `plans/windows-network-fallback-plan.md` proves an HNS, WFP, or
   inside-container ETW source with reliable container attribution.
3. **M3-C: Listen/failure decision — deferred.** Listen and failed
   connect metrics remain omitted on Windows. ETW did not prove the
   required fields, and the host TCP owner table did not include a
   process-isolated container listener. Both metrics are deferred to
   `plans/windows-network-fallback-plan.md`.

## Verification Log

- 2026-06-17: On the Horde Windows VM, `logman start ... -p
  Microsoft-Windows-Kernel-Network 0x30 0x4 -ets` succeeded, proving
  the current user can create the required real-time ETW session.
- 2026-06-17: `Get-WinEvent -ListProvider` on the Horde Windows VM
  verified `Microsoft-Windows-Kernel-Network` event IDs `10,11,12,13,
  15,16,18,26,27,28,29,31,32,34,42,43,58,59` and field names
  `PID,size,daddr,saddr,dport,sport,startime,endtime,seqnum,connid`
  for TCP/UDP events used by M3-A.
- 2026-06-17: A Hyper-V isolated container curl workload emitted
  network ETW events, but event PIDs did not match Docker `State.Pid`;
  Hyper-V per-container attribution is therefore not accepted for M3-A.
- 2026-06-17: A process-isolated Windows container ran successfully on
  the Horde VM, Docker `top` returned host PIDs for the container's
  running and exec processes, and a curl workload emitted
  `Microsoft-Windows-Kernel-Network` TCP event IDs including
  `10,11,12,13,15,16,18`.
- 2026-06-17: M3-A implementation verified on the Horde Windows VM with
  a process-isolated `mcr.microsoft.com/windows/nanoserver:ltsc2025`
  container named `coroot-m3-curl`. The container ran a throttled
  `curl.exe` download, Docker `top` showed the host `curl.exe` PID, and
  the agent emitted samples for logical container ID
  `/docker/coroot-m3-curl`:
  `container_net_tcp_active_connections{destination="92.223.96.6:80",
  actual_destination="92.223.96.6:80"} 1`,
  `container_net_tcp_bytes_sent_total{destination="92.223.96.6:80",
  actual_destination="92.223.96.6:80"} 196`, and
  `container_net_tcp_successful_connects_total{destination="92.223.96.6:80",
  actual_destination="92.223.96.6:80"} 1`.
- 2026-06-17: Windows-only unit binaries
  `coroot-etwtracer.test.exe` and `coroot-containers.test.exe` passed on
  the Horde Windows VM. Repository gates `make lint`, `make test`, and
  `make crossbuild-check` passed on the Linux workspace.
- 2026-06-17: M3-B DNS attribution proof failed on the Horde Windows VM.
  `Get-WinEvent -ListProvider Microsoft-Windows-DNS-Client` verified
  event IDs `3006/3008/3010/3011/3016/3018/3020` and fields
  `QueryName,QueryType,Status,ResponseStatus,QueryResults,ClientPID`,
  but process-isolated container `curl.exe` DNS lookups did not appear
  as host DNS Client events with the container PID. Captured DNS Client
  events during the test carried host process PID `5964`
  (`consul.exe`) for host background lookups, while Docker `top` showed
  the container `curl.exe` PID separately. A
  `Microsoft-Windows-Winsock-NameResolution` capture also did not emit
  the unique container query. DNS metrics are therefore deferred to the
  Windows network fallback plan.
- 2026-06-17: M3-C listen attribution proof failed on the Horde Windows
  VM. A process-isolated container ran `coroot-node-agent-m3c.exe`
  listening on `0.0.0.0:18090`, and Docker `top` showed the listener
  process PID. Host `Get-NetTCPConnection -OwningProcess <pid>`,
  `Get-NetTCPConnection -LocalPort 18090`, and `netstat -ano` did not
  show that listener. `Get-NetTCPConnection` has no all-compartments
  option on this VM. `container_net_tcp_listen_info` remains omitted on
  Windows and deferred to the fallback plan.

## Acceptance Criteria

- [x] **M3-CRIT-1:** `make crossbuild-check` and `make test` pass.
- [x] **M3-CRIT-2:** The ETW source map records exact provider names,
      event IDs, payload fields, and privileges for each implemented
      event.
- [x] **M3-CRIT-3:** Windows builds do not import Linux-only
      `ebpftracer` packages or types.
- [x] **M3-CRIT-4:** Required TCP and DNS metrics are emitted on
      Windows with Linux-compatible metric names and label keys, or
      each omission is explicitly documented with the failed ETW proof.
- [x] **M3-CRIT-5:** Metric samples are attributed to the correct
      logical container ID for the verification workload.
- [x] **M3-CRIT-6:** Any WFP fallback work is deferred to a separate
      accepted sub-plan.
