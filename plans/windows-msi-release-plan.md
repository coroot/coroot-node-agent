# Windows MSI Release Plan

**Status:** Complete
**Parent:** `plans/windows-service-installer-plan.md`
**Created:** 2026-06-18

## Goal

Add a native Windows Installer package to GitHub releases so operators can
install the Windows service without running repository checkout scripts.
Authenticode signing is intentionally out of scope for this pass.

## Design

- Build a per-machine x64 MSI on GitHub-hosted `windows-latest`.
- Pin the build tooling to WiX Toolset v3.14.1, the latest WiX v3
  maintenance release. WiX v3 is out of community support, but this keeps
  the release path on the last v3 toolchain before the newer maintenance-fee
  binary distribution model.
- Download the WiX v3.14.1 build tools through the `wix` NuGet package at
  build time instead of requiring a runner-level installation.
- Install `coroot-node-agent.exe` to `C:\Program Files\Coroot`.
- Create `C:\ProgramData\Coroot\wal` for the agent WAL.
- Install and start a native Windows service named `coroot-node-agent` as
  `LocalSystem`, with automatic startup and these default arguments:
  `--listen=0.0.0.0:80 --wal-dir="C:\ProgramData\Coroot\wal"`.
- Expose `LISTENADDRESS` as an MSI public property so release users can
  override the service listen address with `msiexec`.
- Continue publishing the raw `.exe` release asset alongside the MSI.

## Verification Procedure

Local static validation:

1. Parse `scripts/build-windows-msi.ps1` with PowerShell.
2. Parse `packaging/windows/coroot-node-agent.wxs` as XML.
3. Run `make lint`, `make test`, and `make crossbuild-check`.

Windows build validation:

1. Build `coroot-node-agent-windows-amd64.exe`.
2. Run `scripts\build-windows-msi.ps1 -BinaryPath <exe> -Version <semver>`.
3. Verify `dist\coroot-node-agent-windows-amd64.msi` is produced.

Release validation:

1. Create a GitHub release from a semver tag.
2. Verify the release contains `coroot-node-agent-windows-amd64.exe` and
   `coroot-node-agent-windows-amd64.msi`.

## Verification Log

- 2026-06-18: Static validation passed on Linux: PowerShell parser accepted
  `scripts/build-windows-msi.ps1`, `xmllint` accepted
  `packaging/windows/coroot-node-agent.wxs`, and the GitHub release workflow
  parsed as YAML.
- 2026-06-18: Windows 11 VM build validation produced
  `C:\Temp\coroot-node-agent-msi\dist\coroot-node-agent-windows-amd64.msi`
  using WiX v3.14.1 and a test `v1.2.3` product version.
- 2026-06-18: Windows 11 VM MSI install/start/scrape validation passed with
  `LISTENADDRESS=127.0.0.1:18089`; the service reached `Running` and
  `/metrics` emitted
  `node_agent_info{machine_id="422bdee8088a455997e3f311384a843e",system_uuid="",version="1.2.3"} 1`.
- 2026-06-18: Initial uninstall observation was inconclusive because the
  Windows VM temporarily stopped completing SSH banner exchange after
  `msiexec /x` was launched. When SSH recovered, the uninstall log showed
  removal status 0, and the service was removed.
- 2026-06-18: The first MSI installed the service binary under the source
  asset name (`coroot-node-agent-windows-amd64.exe`). The WiX `File` element
  now forces the installed filename to `coroot-node-agent.exe`.
- 2026-06-18: Corrected Windows 11 VM MSI install/start/scrape/uninstall
  validation passed with `LISTENADDRESS=127.0.0.1:18091`. The installed
  service path was
  `"C:\Program Files\Coroot\coroot-node-agent.exe" --listen=127.0.0.1:18091 --wal-dir="C:\ProgramData\Coroot\wal"`,
  `/metrics` emitted `node_agent_info`, `msiexec /x` returned 0, the service
  was absent after uninstall, and
  `C:\Program Files\Coroot\coroot-node-agent.exe` was removed.
- 2026-06-19: GitHub release `v1.32.6` exposed a Windows CI checkout gap:
  Git for Windows failed to check out the long fixture path under
  `cgroup/fixtures/cgroup/kubepods.slice/...` until `core.longpaths=true`
  was configured before `actions/checkout`.
- 2026-06-19: Commit `ca058eb` enabled Git long paths before Windows
  checkouts in CI, release, and Windows integration workflows. `make lint`,
  `make test`, and `make crossbuild-check` passed before commit.
- 2026-06-19: GitHub release `v1.32.7` produced and uploaded
  `coroot-node-agent-windows-amd64.exe` and
  `coroot-node-agent-windows-amd64.msi`. The MSI asset had content type
  `application/x-msi`, size `14688256`, and digest
  `sha256:dba514c0e8c068e8bc728b0ef77566abe014b668cbab91fab0699ed09e6ad5ec`.
  The full release workflow still failed in the Linux binary extraction
  step because the workflow used the mixed-case repository owner in
  `ghcr.io/NVShawn/coroot-node-agent`; Docker requires lowercase image
  references.
- 2026-06-19: Commit `39a888e` fixed the release workflow by deriving a
  lowercase image reference before Docker metadata, build, and extraction
  steps. `make lint`, `make test`, and `make crossbuild-check` passed before
  commit.
- 2026-06-19: GitHub release `v1.32.8` completed successfully end-to-end.
  The release contains Linux `amd64` and `arm64` binaries, the Windows `.exe`,
  and `coroot-node-agent-windows-amd64.msi`. The MSI asset had content type
  `application/x-msi`, size `14688256`, and digest
  `sha256:937e9a41316772fe49bd2a3049b99aecbec134a5a7c68cfed90f805c76fed4b3`.

## Acceptance Criteria

- [x] **MSI-CRIT-1:** The repository contains a WiX v3 source file that
      installs the Windows binary as the `coroot-node-agent` service.
- [x] **MSI-CRIT-2:** `scripts/build-windows-msi.ps1` builds the MSI from a
      supplied Windows binary and normalizes semver tags to Windows
      Installer-compatible product versions.
- [x] **MSI-CRIT-3:** GitHub release CI runs MSI packaging on
      `windows-latest` and uploads `coroot-node-agent-windows-amd64.msi` as
      a release asset.
- [x] **MSI-CRIT-4:** User documentation explains the MSI install,
      configurable `LISTENADDRESS` property, uninstall command, and unsigned
      package status.
- [x] **MSI-CRIT-5:** A created GitHub release contains the MSI artifact.
- [x] **MSI-CRIT-6:** MSI uninstall is verified on Windows after the VM SSH
      service recovers or another Windows validation host is available.
