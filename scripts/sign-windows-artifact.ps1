[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path,
    [string]$CertificateBase64 = $env:WINDOWS_SIGNING_CERT_BASE64,
    [string]$CertificatePassword = $env:WINDOWS_SIGNING_CERT_PASSWORD,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$SignToolPath = ""
)

$ErrorActionPreference = "Stop"

function Get-SignToolPath {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "signtool.exe not found at $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $kitRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path -LiteralPath $kitRoot) {
        $candidate = Get-ChildItem -LiteralPath $kitRoot -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) {
            return $candidate.FullName
        }
    }

    throw "signtool.exe was not found. Install the Windows SDK or pass -SignToolPath."
}

if (-not $CertificateBase64) {
    throw "CertificateBase64 is required. Set WINDOWS_SIGNING_CERT_BASE64 or pass -CertificateBase64."
}
if (-not $CertificatePassword) {
    throw "CertificatePassword is required. Set WINDOWS_SIGNING_CERT_PASSWORD or pass -CertificatePassword."
}

$signtool = Get-SignToolPath -ExplicitPath $SignToolPath
$tempRoot = $env:RUNNER_TEMP
if (-not $tempRoot) {
    $tempRoot = $env:TEMP
}
if (-not $tempRoot) {
    $tempRoot = [System.IO.Path]::GetTempPath()
}
$pfxPath = Join-Path $tempRoot "coroot-windows-signing.pfx"

try {
    [System.IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($CertificateBase64))

    foreach ($item in $Path) {
        if (-not (Test-Path -LiteralPath $item -PathType Leaf)) {
            throw "Artifact not found: $item"
        }
        $artifact = (Resolve-Path -LiteralPath $item).Path
        & $signtool sign `
            /fd SHA256 `
            /tr $TimestampUrl `
            /td SHA256 `
            /f $pfxPath `
            /p $CertificatePassword `
            $artifact
        if ($LASTEXITCODE -ne 0) {
            throw "signtool sign failed for $artifact with exit code $LASTEXITCODE"
        }

        & $signtool verify /pa /tw $artifact
        if ($LASTEXITCODE -ne 0) {
            throw "signtool verify failed for $artifact with exit code $LASTEXITCODE"
        }
        Write-Output "Signed and verified $artifact"
    }
}
finally {
    Remove-Item -Force $pfxPath -ErrorAction SilentlyContinue
}
