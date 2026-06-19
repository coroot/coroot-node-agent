[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [string]$Version = "0.0.0",
    [string]$OutputDir = (Join-Path (Get-Location).Path "dist"),
    [string]$WixVersion = "3.14.1",
    [string]$WixSource = (Join-Path (Join-Path $PSScriptRoot "..") "packaging\windows\coroot-node-agent.wxs"),
    [string]$WixToolsDir = ""
)

$ErrorActionPreference = "Stop"

function ConvertTo-WixProductVersion {
    param([string]$InputVersion)

    $trimmed = $InputVersion.Trim()
    if ($trimmed.StartsWith("v")) {
        $trimmed = $trimmed.Substring(1)
    }
    if ($trimmed -notmatch "^([0-9]+)\.([0-9]+)\.([0-9]+)") {
        throw "Version '$InputVersion' must begin with a semver-compatible major.minor.patch value for MSI packaging."
    }

    $major = [int]$Matches[1]
    $minor = [int]$Matches[2]
    $patch = [int]$Matches[3]
    if ($major -gt 255 -or $minor -gt 255 -or $patch -gt 65535) {
        throw "Version '$InputVersion' exceeds Windows Installer ProductVersion limits."
    }

    return "$major.$minor.$patch"
}

function Get-WixTools {
    param(
        [string]$Version,
        [string]$ToolsDir
    )

    if ($ToolsDir) {
        $resolvedToolsDir = (Resolve-Path -LiteralPath $ToolsDir).Path
    } else {
        $cacheRoot = $env:RUNNER_TEMP
        if (-not $cacheRoot) {
            $cacheRoot = $env:TEMP
        }
        if (-not $cacheRoot) {
            $cacheRoot = Join-Path (Get-Location).Path ".tmp"
        }

        $packageRoot = Join-Path $cacheRoot "wix-$Version"
        $resolvedToolsDir = Join-Path $packageRoot "tools"
        $candlePath = Join-Path $resolvedToolsDir "candle.exe"
        $lightPath = Join-Path $resolvedToolsDir "light.exe"
        if (-not ((Test-Path -LiteralPath $candlePath) -and (Test-Path -LiteralPath $lightPath))) {
            Remove-Item -Recurse -Force $packageRoot -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Force $packageRoot | Out-Null

            $nupkgPath = Join-Path $cacheRoot "wix.$Version.nupkg"
            $zipPath = Join-Path $cacheRoot "wix.$Version.zip"
            $packageUri = "https://www.nuget.org/api/v2/package/wix/$Version"
            Remove-Item -Force $nupkgPath, $zipPath -ErrorAction SilentlyContinue

            $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
            if ($curl) {
                & $curl.Source `
                    -fL `
                    --retry 3 `
                    --retry-delay 2 `
                    --connect-timeout 30 `
                    --max-time 300 `
                    -o $nupkgPath `
                    $packageUri
                if ($LASTEXITCODE -ne 0) {
                    throw "curl.exe failed to download WiX $Version with exit code $LASTEXITCODE"
                }
            } else {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest `
                    -UseBasicParsing `
                    -Uri $packageUri `
                    -OutFile $nupkgPath
            }

            $downloadedPackage = Get-Item -LiteralPath $nupkgPath
            if ($downloadedPackage.Length -eq 0) {
                throw "Downloaded WiX package is empty: $nupkgPath"
            }
            Copy-Item -LiteralPath $nupkgPath -Destination $zipPath -Force
            Expand-Archive -LiteralPath $zipPath -DestinationPath $packageRoot -Force
        }
    }

    $candle = Join-Path $resolvedToolsDir "candle.exe"
    $light = Join-Path $resolvedToolsDir "light.exe"
    if (-not (Test-Path -LiteralPath $candle)) {
        throw "WiX candle.exe not found in $resolvedToolsDir"
    }
    if (-not (Test-Path -LiteralPath $light)) {
        throw "WiX light.exe not found in $resolvedToolsDir"
    }

    return @{
        Candle = $candle
        Light = $light
    }
}

if ($env:OS -ne "Windows_NT") {
    throw "Building the Windows MSI requires Windows because WiX v3 tools are Windows executables."
}
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Binary not found: $BinaryPath"
}
if (-not (Test-Path -LiteralPath $WixSource -PathType Leaf)) {
    throw "WiX source not found: $WixSource"
}

$productVersion = ConvertTo-WixProductVersion $Version
$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
$resolvedWixSource = (Resolve-Path -LiteralPath $WixSource).Path
if ([System.IO.Path]::IsPathRooted($OutputDir)) {
    $resolvedOutputDir = $OutputDir
} else {
    $resolvedOutputDir = Join-Path (Get-Location).Path $OutputDir
}
New-Item -ItemType Directory -Force $resolvedOutputDir | Out-Null

$wixTools = Get-WixTools -Version $WixVersion -ToolsDir $WixToolsDir
$wixObj = Join-Path $resolvedOutputDir "coroot-node-agent-windows-amd64.wixobj"
$outputMsi = Join-Path $resolvedOutputDir "coroot-node-agent-windows-amd64.msi"

& $wixTools.Candle `
    -nologo `
    -arch x64 `
    "-dProductVersion=$productVersion" `
    "-dSourceBinary=$resolvedBinary" `
    -out $wixObj `
    $resolvedWixSource
if ($LASTEXITCODE -ne 0) {
    throw "WiX candle.exe failed with exit code $LASTEXITCODE"
}

& $wixTools.Light `
    -nologo `
    -out $outputMsi `
    $wixObj
if ($LASTEXITCODE -ne 0) {
    throw "WiX light.exe failed with exit code $LASTEXITCODE"
}

Write-Output "Built $outputMsi"
