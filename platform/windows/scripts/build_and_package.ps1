# Build the TrustTunnel Windows adapter distribution package in one command.
#
# Composition only: assembles the staging directory via build.ps1, then
# creates the ZIP archive via package.ps1. The stage scripts are also usable
# individually (e.g. CI signs the binaries between the two stages — see the
# deploy-windows workflow).
#
# Usage:
#   .\build_and_package.ps1 -Version <semver> [-Arch <x86_64|aarch64>] [-BuildType <RelWithDebInfo|Release|Debug>] [-WintunUrl <url>]
#
# Examples:
#   .\build_and_package.ps1 -Version 1.2.3                     # Build x86_64 RelWithDebInfo
#   .\build_and_package.ps1 -Version 1.2.3 -Arch aarch64       # Build arm64
#
# Builds with the MSVC environment of the session it runs in.
# See build.ps1 for the developer-prompt requirements.
#
# Output:
#   artifacts/trusttunnel-client-windows-<version>-<arch>.zip

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    [ValidateSet("x86_64", "aarch64")]
    [string]$Arch = "x86_64",
    [string]$BuildType = "RelWithDebInfo",
    [string]$WintunUrl = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PlatformDir = Split-Path -Parent $ScriptDir   # platform/windows/
$StagingDir = Join-Path (Join-Path $PlatformDir "staging") "trusttunnel-client-windows-$Version-$Arch"

& (Join-Path $ScriptDir "build.ps1") `
    -Version $Version `
    -Arch $Arch `
    -BuildType $BuildType `
    -WintunUrl $WintunUrl
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& (Join-Path $ScriptDir "package.ps1") `
    -StagingDir $StagingDir
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
