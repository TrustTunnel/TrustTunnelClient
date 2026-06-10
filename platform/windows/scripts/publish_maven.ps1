# Publish the TrustTunnel Windows adapter package to GitHub Maven Packages.
#
# Architecture names match the `build-windows` release job: x86_64, i686, aarch64.
# The artifact is published under the same Maven coordinates convention used by
# the Android/Apple adapters (groupId com.adguard.trusttunnel).
#
# Prerequisites:
#   - A GitHub Personal Access Token with `write:packages` scope
#   - The ZIP archive built by build_package.ps1
#
# Usage:
#   .\publish_maven.ps1 -Version 1.2.3 -Arch x86_64
#   .\publish_maven.ps1 -Version 1.2.3 -Arch i686
#   .\publish_maven.ps1 -Version 1.2.3 -Arch aarch64
#
# Environment variables (alternatively pass as parameters):
#   TOKEN - GitHub PAT with write:packages scope

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    [Parameter(Mandatory=$true)]
    [ValidateSet("x86_64", "i686", "aarch64")]
    [string]$Arch,
    [string]$GitHubToken = $env:TOKEN,
    [string]$Repository = "TrustTunnel/TrustTunnelClient"
)

$ErrorActionPreference = "Stop"

if (-not $GitHubToken) {
    Write-Error "GitHub token required. Set TOKEN env var or pass as parameter."
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ArtifactsDir = Join-Path (Split-Path -Parent $ScriptDir) "artifacts"
$ArtifactId = "trusttunnel-client-windows-$Arch"
$GroupPath = "com/adguard/trusttunnel"
$ZipFileName = "$ArtifactId-$Version.zip"
$ZipFile = Join-Path $ArtifactsDir $ZipFileName

if (-not (Test-Path $ZipFile)) {
    Write-Error "Package not found: $ZipFile"
    Write-Error "Run build_package.ps1 first."
    exit 1
}

Write-Host "=== Publishing to GitHub Maven Packages ===" -ForegroundColor Cyan
Write-Host "Version:    $Version"
Write-Host "Arch:       $Arch"
Write-Host "Package:    $ZipFile"
Write-Host ""

$MavenUrl = "https://maven.pkg.github.com/$Repository/$GroupPath/$ArtifactId/$Version/$ZipFileName"

Write-Host "Uploading..." -NoNewline

$headers = @{
    "Authorization" = "Bearer $GitHubToken"
}

try {
    Invoke-RestMethod -Method Put -Uri $MavenUrl -InFile $ZipFile -Headers $headers -ContentType "application/octet-stream"
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Error $_
    exit 1
}

Write-Host ""
Write-Host "=== Published successfully ===" -ForegroundColor Green
