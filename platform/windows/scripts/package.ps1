# Package a staged TrustTunnel Windows adapter directory into a ZIP archive.
#
# Companion to build.ps1: takes an assembled staging directory
# (typically staging/trusttunnel-client-windows-<version>-<arch>,
# optionally after signing) and creates
# artifacts/trusttunnel-client-windows-<version>-<arch>.zip.
#
# The ZIP name is derived from the staging directory name, so the staging
# dir naming convention is part of the package contract.
#
# Usage:
#   .\package.ps1 -StagingDir <path-to-staging-dir>
#
# Example:
#   .\package.ps1 -StagingDir ..\staging\trusttunnel-client-windows-1.2.3-x86_64

param(
    [Parameter(Mandatory=$true)]
    [string]$StagingDir
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PlatformDir = Split-Path -Parent $ScriptDir   # platform/windows/
$ArtifactsDir = Join-Path $PlatformDir "artifacts"

$StagingDir = (Resolve-Path $StagingDir).Path

if (-not (Test-Path (Join-Path $StagingDir "bin"))) {
    Write-Error "Not a valid staging directory (bin/ missing): $StagingDir"
    exit 1
}

Write-Host "=== TrustTunnel Windows Adapter Packaging ===" -ForegroundColor Cyan
Write-Host "Staging: $StagingDir"
Write-Host ""

# ---------------------------------------------------------------------------
# Create ZIP archive
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $ArtifactsDir | Out-Null

# The ZIP name is the staging directory name; the dir already follows the
# trusttunnel-client-windows-<version>-<arch> convention.
$zipName = "$(Split-Path -Leaf $StagingDir).zip"
$zipPath = Join-Path $ArtifactsDir $zipName

# Remove existing zip if present
if (Test-Path $zipPath) {
    Remove-Item $zipPath
}

Compress-Archive -Path (Join-Path $StagingDir "*") -DestinationPath $zipPath

Write-Host ""
Write-Host "=== Package created ===" -ForegroundColor Green
Write-Host "Archive: $zipPath"
Write-Host ""

# Show contents
Write-Host "--- Archive contents ---" -ForegroundColor Cyan
Add-Type -Assembly System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
$archive.Entries | ForEach-Object { Write-Host "  $($_.FullName) ($($_.CompressedLength) bytes)" }
$archive.Dispose()

Write-Host ""
Write-Host "To publish to GitHub Maven Packages:" -ForegroundColor Yellow
Write-Host "  See scripts/publish_maven.ps1"
exit 0
