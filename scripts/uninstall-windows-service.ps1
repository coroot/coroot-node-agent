param(
    [string]$ServiceName = "coroot-node-agent",
    [string]$InstallDir = "C:\Program Files\Coroot",
    [string]$DataDir = "C:\ProgramData\Coroot",
    [switch]$KeepData
)

$ErrorActionPreference = "Stop"

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus("Stopped", "00:00:30")
    }
    sc.exe delete $ServiceName | Out-Null
    Write-Output "Deleted $ServiceName"
}

Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
if (-not $KeepData) {
    Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
}
