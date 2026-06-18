param(
    [string]$BinaryPath = ".\coroot-node-agent.exe",
    [string]$InstallDir = "C:\Program Files\Coroot",
    [string]$DataDir = "C:\ProgramData\Coroot",
    [string]$ServiceName = "coroot-node-agent",
    [string]$DisplayName = "Coroot Node Agent",
    [string]$Listen = "0.0.0.0:80",
    [string]$StartupType = "Automatic",
    [string[]]$AdditionalArgs = @(),
    [switch]$NoStart,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    throw "Binary not found: $BinaryPath"
}

$resolvedBinary = (Resolve-Path $BinaryPath).Path
$installBinary = Join-Path $InstallDir "coroot-node-agent.exe"
$walDir = Join-Path $DataDir "wal"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and -not $Force) {
    throw "Service $ServiceName already exists. Use -Force to replace it."
}
if ($existing) {
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $existing.WaitForStatus("Stopped", "00:00:30")
    }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

New-Item -ItemType Directory -Force $InstallDir, $DataDir, $walDir | Out-Null
Copy-Item $resolvedBinary $installBinary -Force

$args = @("--listen=$Listen", "--wal-dir=$walDir") + $AdditionalArgs
$binaryPathName = '"' + $installBinary + '" ' + ($args -join " ")

New-Service `
    -Name $ServiceName `
    -DisplayName $DisplayName `
    -Description "Collects Windows node and container telemetry for Coroot" `
    -BinaryPathName $binaryPathName `
    -StartupType $StartupType | Out-Null

if (-not $NoStart) {
    Start-Service -Name $ServiceName
}

Write-Output "Installed $ServiceName"
Write-Output $binaryPathName
