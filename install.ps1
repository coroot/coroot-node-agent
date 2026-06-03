<#
.SYNOPSIS
    Downloads the latest coroot-windows-agent release and installs it as a Windows
    service via the MSI package. Re-running upgrades an existing installation.

    Parameters can be passed as flags or via COROOT_* environment variables, so the
    script can be piped straight to PowerShell, e.g.:
      $env:COROOT_COLLECTOR_ENDPOINT='http://coroot:8080'; $env:COROOT_API_KEY='<KEY>'
      iwr -useb https://raw.githubusercontent.com/coroot/coroot-node-agent/main/install.ps1 | iex
.EXAMPLE
    .\install.ps1 -CollectorEndpoint http://coroot:8080 -ApiKey <API_KEY>
#>
[CmdletBinding()]
param(
    [string]$CollectorEndpoint = $env:COROOT_COLLECTOR_ENDPOINT,
    [string]$ApiKey = $env:COROOT_API_KEY,
    [string]$ScrapeInterval = $(if ($env:COROOT_SCRAPE_INTERVAL) { $env:COROOT_SCRAPE_INTERVAL } else { "15s" }),
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# #Requires can't be used when the script is piped to iex, so check at runtime.
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Please run this in an elevated PowerShell (Run as administrator)." }
if (-not $CollectorEndpoint) { throw "CollectorEndpoint is required (pass -CollectorEndpoint or set `$env:COROOT_COLLECTOR_ENDPOINT)." }
if (-not $ApiKey) { throw "ApiKey is required (pass -ApiKey or set `$env:COROOT_API_KEY)." }

$repo = "coroot/coroot-node-agent"

# Resolve "latest" without the GitHub API (no rate limit): follow the /releases/latest
# redirect and read the tag from the Location header.
if ($Version -eq "latest") {
    Write-Host "Finding the latest release..."
    $req = [System.Net.HttpWebRequest]::Create("https://github.com/$repo/releases/latest")
    $req.AllowAutoRedirect = $false
    $req.Method = "HEAD"
    $resp = $req.GetResponse()
    try { $location = $resp.Headers["Location"] } finally { $resp.Close() }
    if (-not $location) { throw "Could not resolve the latest release" }
    $Version = ($location -split "/")[-1]
}
# Resolve the native OS architecture from the machine environment in the registry.
# This works on any .NET version (RuntimeInformation needs .NET Framework 4.7.1+,
# which isn't present on older Windows) and reflects the OS architecture even when
# PowerShell runs as a 32-bit / x64-emulated process.
$osArch = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE
switch ($osArch) {
    "AMD64" { $arch = "amd64" }
    "ARM64" { $arch = "arm64" }
    default { throw "Unsupported architecture: $osArch" }
}
Write-Host "Installing coroot-windows-agent $Version ($arch)"

$msiUrl = "https://github.com/$repo/releases/download/$Version/coroot-windows-agent-$arch.msi"
$msiPath = Join-Path $env:TEMP "coroot-windows-agent-$Version-$arch.msi"
Write-Host "Downloading $msiUrl"
Invoke-WebRequest -UseBasicParsing -Uri $msiUrl -OutFile $msiPath

$log = Join-Path $env:TEMP "coroot-windows-agent-install.log"
$msiArgs = @(
    "/i", "`"$msiPath`"", "/qn", "/norestart", "/l*v", "`"$log`"",
    "COLLECTOR_ENDPOINT=`"$CollectorEndpoint`"",
    "API_KEY=`"$ApiKey`"",
    "SCRAPE_INTERVAL=`"$ScrapeInterval`""
)
Write-Host "Running the installer..."
$p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($p.ExitCode -ne 0) {
    throw "Installation failed (msiexec exit code $($p.ExitCode)). See $log"
}
Remove-Item $msiPath -Force -ErrorAction SilentlyContinue

$svc = Get-Service coroot-windows-agent -ErrorAction SilentlyContinue
Write-Host "Done. Service 'coroot-windows-agent' status: $($svc.Status)"
Write-Host "Logs:      Get-WinEvent -ProviderName coroot-windows-agent   (or Event Viewer > Windows Logs > Application)"
Write-Host "Configure: set machine env vars like COROOT_SCRAPE_INTERVAL, then 'Restart-Service coroot-windows-agent'"
Write-Host "Uninstall: Settings > Apps, or  msiexec /x (find the product under installed programs)"
