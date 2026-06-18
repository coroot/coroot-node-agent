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
metrics, and partial ETW TCP metrics for process-isolated Windows Docker
containers.

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
