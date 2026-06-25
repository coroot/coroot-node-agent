# Windows Quickstart

This branch supports running `coroot-node-agent` on Windows as either a
foreground process or a native Windows service. The Windows service mode
is selected automatically when the binary is launched by the Windows
Service Control Manager; no service-specific agent flag is required.
Final support still requires Windows Server 2022 validation; see
`docs/windows-support-matrix.md`.

## Requirements

- Windows 11 for current development validation. Before final support,
  repeat validation on Windows Server 2022 unless the support matrix is
  changed.
- Administrator privileges for service installation and ETW access.
- A writable WAL directory, for example `C:\ProgramData\Coroot\wal`.
- Optional: a Windows Docker Engine if container discovery, Docker JSON
  log parsing, or process-isolated Docker TCP metrics are needed.

Current Windows metrics include startup, node-level metrics, Docker
container discovery, Docker `json-file` stdout/stderr log-pattern
metrics, Windows Event Log pattern metrics, and partial ETW TCP metrics
for process-isolated Windows Docker containers.

## Build

From the repository root:

```powershell
$env:GOOS = "windows"
go build -o coroot-node-agent.exe .
```

## Foreground Run

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\Coroot\wal | Out-Null
.\coroot-node-agent.exe --listen=127.0.0.1:18080 --wal-dir=C:\ProgramData\Coroot\wal
```

In another PowerShell session:

```powershell
(Invoke-WebRequest -UseBasicParsing http://127.0.0.1:18080/metrics).Content
```

## Windows Event Logs

By default, the Windows binary subscribes to future events from the
`Application` and `System` channels and exposes
`windows_event_log_messages_total` with `channel`, `provider`,
`event_id`, `level`, `pattern_hash`, and `sample` labels.

Add channels by repeating `--windows-event-log-channel`:

```powershell
.\coroot-node-agent.exe `
  --listen=127.0.0.1:18080 `
  --wal-dir=C:\ProgramData\Coroot\wal `
  --windows-event-log-channel Application `
  --windows-event-log-channel System `
  --windows-event-log-channel Security
```

Disable Event Log collection without disabling container log parsing:

```powershell
.\coroot-node-agent.exe --disable-windows-event-log-monitoring
```

If `--logs-endpoint` or `--collector-endpoint` is configured, parsed
Event Log patterns are also sent through OTLP logs with
`eventlog.channel`, `eventlog.provider`, `eventlog.event_id`, and
`pattern.hash` attributes.

## OpenTelemetry Trace Export

Windows trace export is supported for agent lifecycle spans. It is not
Linux L7 tracing parity: HTTP, database, DNS, and per-container trace
spans are still Linux-only.

Send lifecycle spans to an OTLP HTTP trace endpoint:

```powershell
.\coroot-node-agent.exe `
  --listen=127.0.0.1:18080 `
  --wal-dir=C:\ProgramData\Coroot\wal `
  --traces-endpoint=https://collector.example.com/v1/traces `
  --traces-sampling=1.0
```

When `--collector-endpoint` is set and `--traces-endpoint` is omitted,
the Windows binary derives `--traces-endpoint=<collector>/v1/traces`.

## Windows Profiling

Windows profiling is disabled by default. The supported MVP mode is
agent self CPU profiling: the agent periodically collects a Go CPU pprof
for `coroot-node-agent.exe` itself and uploads it to the configured
profiles endpoint. Host process profiling and container profiling are
future work.

```powershell
.\coroot-node-agent.exe `
  --listen=127.0.0.1:18080 `
  --wal-dir=C:\ProgramData\Coroot\wal `
  --profiles-endpoint=https://collector.example.com/v1/profiles `
  --windows-profile=agent-cpu `
  --windows-profile-interval=1m `
  --windows-profile-duration=10s
```

When `--collector-endpoint` is set and `--profiles-endpoint` is omitted,
the Windows binary derives `--profiles-endpoint=<collector>/v1/profiles`.

## Service Install

Run PowerShell as Administrator:

```powershell
.\scripts\install-windows-service.ps1 `
  -BinaryPath .\coroot-node-agent.exe `
  -Listen 0.0.0.0:80
```

Start and verify:

```powershell
Start-Service coroot-node-agent
Get-Service coroot-node-agent
(Invoke-WebRequest -UseBasicParsing http://127.0.0.1:80/metrics).Content
```

For Docker-backed container metrics, make sure the service account can
access the Windows Docker Engine named pipe. The default `LocalSystem`
account is the validated service account on the development VM.

## Release MSI

GitHub releases publish `coroot-node-agent-windows-amd64.msi` alongside the
raw Windows `.exe`. The MSI is built on GitHub-hosted Windows runners with
WiX Toolset v3.14.1 and is not Authenticode-signed yet.

Run PowerShell as Administrator:

```powershell
msiexec /i .\coroot-node-agent-windows-amd64.msi
```

The MSI installs `C:\Program Files\Coroot\coroot-node-agent.exe`, creates
`C:\ProgramData\Coroot\wal`, and starts the `coroot-node-agent` service as
`LocalSystem` with `--listen=0.0.0.0:80`. Override the listen address at
install time if needed:

```powershell
msiexec /i .\coroot-node-agent-windows-amd64.msi LISTENADDRESS=127.0.0.1:18080
```

Uninstall:

```powershell
msiexec /x .\coroot-node-agent-windows-amd64.msi
```

## Stop And Uninstall

Run PowerShell as Administrator:

```powershell
.\scripts\uninstall-windows-service.ps1
```

Remove the binary and runtime data if desired:

```powershell
Remove-Item -Recurse -Force "C:\Program Files\Coroot", "C:\ProgramData\Coroot"
```

Use `-KeepData` with `scripts\uninstall-windows-service.ps1` to remove
the service and installed binary while preserving
`C:\ProgramData\Coroot`.

## Kubernetes Status

The existing `manifests/coroot-node-agent.yaml` DaemonSet is Linux-only
and is constrained to `kubernetes.io/os: linux`. Windows Kubernetes
deployment via a HostProcess container image is deferred until a
validated Windows Server Kubernetes node and a publishable Windows image
are available.
