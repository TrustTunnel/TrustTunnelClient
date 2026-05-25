# Publish the TrustTunnel Windows adapter package to GitHub Maven Packages.
#
# Prerequisites:
#   - A GitHub Personal Access Token with `write:packages` scope
#   - The ZIP archive built by build_package.ps1
#
# Usage:
#   .\publish_maven.ps1 -Version 1.2.3 -Arch amd64
#   .\publish_maven.ps1 -Version 1.2.3 -Arch arm64
#
# Environment variables (alternatively pass as parameters):
#   GITHUB_TOKEN - GitHub PAT with write:packages scope

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    [Parameter(Mandatory=$true)]
    [ValidateSet("amd64", "arm64")]
    [string]$Arch,
    [string]$GitHubToken = $env:GITHUB_TOKEN,
    [string]$Repository = "TrustTunnel/TrustTunnelClient"
)

$ErrorActionPreference = "Stop"

if (-not $GitHubToken) {
    Write-Error "GitHub token required. Set GITHUB_TOKEN env var or pass as parameter."
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ArtifactsDir = Join-Path (Split-Path -Parent $ScriptDir) "artifacts"
$ZipFileName = "trusttunnel-client-windows-$Arch-$Version.zip"
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

$MavenUrl = "https://maven.pkg.github.com/$Repository/com/adguard/trusttunnel/trusttunnel-client-windows-$Arch/$Version/$ZipFileName"

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
