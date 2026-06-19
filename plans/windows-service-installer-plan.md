# Windows Service Installer Plan

**Status:** Complete
**Parent:** `plans/windows-port-plan.md` M5
**Created:** 2026-06-17

## Goal

Make the Windows build installable and operable as a Windows service,
with a documented procedure that can be validated end-to-end on the
Windows VM.

M5 completes the first Windows packaging path through a native Windows
Service Control Manager integration. Kubernetes HostProcess container
deployment is deferred until a Windows Server Kubernetes node and a
publishable Windows image build are available for validation.

## Design

- The shared agent startup path is exposed as `runAgent(ctx)`.
- Linux foreground behavior remains signal-driven through the Linux
  platform entrypoint.
- Windows foreground behavior remains signal-driven when the process is
  interactive.
- When launched by the Windows Service Control Manager, the Windows
  entrypoint uses `golang.org/x/sys/windows/svc` and runs the same
  `runAgent(ctx)` until it receives `Stop` or `Shutdown`.
- The service install procedure uses standard Windows PowerShell service
  management (`New-Service`, `Start-Service`, `Stop-Service`,
  `sc.exe delete`) with existing agent flags embedded in
  `BinaryPathName`. No new agent CLI flag is needed for service mode.
- The existing Kubernetes manifest is explicitly constrained to Linux
  nodes so mixed clusters do not schedule the Linux image on Windows
  nodes by accident.

## Supported Service Procedure

The supported first-pass install path is documented in
`docs/windows-quickstart.md`:

1. Build or copy `coroot-node-agent.exe`.
2. Install it under `C:\Program Files\Coroot`.
3. Create `C:\ProgramData\Coroot` for runtime state.
4. Create a `coroot-node-agent` Windows service with the desired
   existing agent flags.
5. Start the service and scrape `/metrics`.
6. Stop and delete the service for uninstall.

The default documented service account is `LocalSystem`. Operators may
choose a different account if it has the required PDH, ETW, Docker
named-pipe, and filesystem permissions.

## Deferred Work

- Windows MSIX packaging. MSI release packaging is tracked by
  `plans/windows-msi-release-plan.md`.
- Built-in `install` / `uninstall` subcommands. The current branch keeps
  the agent CLI surface unchanged and relies on standard Windows service
  tooling.
- Windows container image publishing.
- Kubernetes Windows HostProcess DaemonSet manifests. This needs
  Windows Server Kubernetes validation and a real Windows image tag
  before it can be marked supported.

## Verification Procedure

On a Windows 11 host:

1. Build `coroot-node-agent.exe` from the current branch.
2. Copy it to `C:\Program Files\Coroot\coroot-node-agent.exe`.
3. Create the service with:
   `New-Service -Name coroot-node-agent -BinaryPathName '"C:\Program Files\Coroot\coroot-node-agent.exe" --listen=127.0.0.1:18087 --wal-dir=C:\ProgramData\Coroot\wal' -StartupType Manual`.
4. Start the service.
5. Scrape `http://127.0.0.1:18087/metrics` and verify
   `node_agent_info` or `node_info` appears.
6. Stop the service.
7. Delete the service.

## Verification Log

- 2026-06-17: `make lint`, `make test`, and `make crossbuild-check`
  passed after the startup refactor.
- 2026-06-17: Windows root test binary `coroot-root.test.exe` passed on
  the Horde Windows VM. The Windows service handler unit test verifies
  that a service `Stop` request cancels the run context and exits with
  code 0.
- 2026-06-17: Live Windows service lifecycle smoke passed on the Horde
  Windows VM. The binary was copied to
  `C:\Program Files\Coroot\coroot-node-agent.exe`, installed as service
  `coroot-node-agent` with
  `"C:\Program Files\Coroot\coroot-node-agent.exe" --listen=127.0.0.1:18087 --min-container-age=0s --wal-dir=C:\ProgramData\Coroot\wal`,
  started, scraped, stopped, and deleted. The scrape emitted:
  `node_agent_info{machine_id="422bdee8088a455997e3f311384a843e",system_uuid="",version="unknown"} 1`.

## Acceptance Criteria

- [x] **M5-CRIT-1:** `make lint`, `make test`, and
      `make crossbuild-check` pass.
- [x] **M5-CRIT-2:** Windows service handler unit coverage proves a
      service `Stop` request cancels the agent run context and returns a
      zero service exit code.
- [x] **M5-CRIT-3:** A Windows VM install/start/scrape/stop/delete
      procedure succeeds using the built Windows binary as a native
      Windows service.
- [x] **M5-CRIT-4:** `docs/windows-quickstart.md` documents Windows
      service install, scrape verification, stop, and uninstall steps
      with current runtime requirements.
- [x] **M5-CRIT-5:** Kubernetes deployment state is explicit: the
      existing Linux manifest is constrained to Linux nodes, and
      Windows HostProcess image/DaemonSet work is documented as
      deferred until it can be validated.
