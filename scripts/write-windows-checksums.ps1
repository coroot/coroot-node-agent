[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

$lines = foreach ($item in $Path) {
    if (-not (Test-Path -LiteralPath $item -PathType Leaf)) {
        throw "Artifact not found: $item"
    }
    $file = (Resolve-Path -LiteralPath $item).Path
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
    "$hash  $([System.IO.Path]::GetFileName($file))"
}

$outputDir = Split-Path -Parent $OutputPath
if ($outputDir) {
    New-Item -ItemType Directory -Force $outputDir | Out-Null
}
Set-Content -LiteralPath $OutputPath -Value $lines -Encoding ascii
Write-Output "Wrote $OutputPath"
