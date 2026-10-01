# Build and stage the TrustTunnel Windows adapter for packaging.
#
# Assembles a complete, self-contained staging directory at
# staging/trusttunnel-client-windows-<version>-<arch>/: built and installed
# binaries plus wintun.dll and licenses. Signing and zipping happen later,
# outside this script (see package_staging.ps1 and the deploy-windows CI job).
#
# Architecture names match the `deploy-windows` release job
# (.github/workflows/deploy-windows.yml): x86_64, aarch64.
#
# Usage:
#   .\build.ps1 -Version <semver> [-Arch <x86_64|aarch64>] [-BuildType <RelWithDebInfo|Release|Debug>] [-WintunUrl <url>]
#
# Examples:
#   .\build.ps1 -Version 1.2.3                     # Build x86_64 RelWithDebInfo
#   .\build.ps1 -Version 1.2.3 -Arch aarch64       # Build arm64
#   .\build.ps1 -Version 1.2.3 -WintunUrl "https://artifactory.example.com/wintun-0.14.1.zip"
#
# Builds with the MSVC environment of the calling session: cl.exe for the
# target architecture must be on PATH, e.g. run from a Visual Studio
# developer prompt such as the x64 Native Tools Command Prompt (launch pwsh
# inside it if needed).
#
# Output:
#   staging/trusttunnel-client-windows-<version>-<arch>/

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
$RootDir = Split-Path -Parent (Split-Path -Parent $PlatformDir) # repo root

Write-Host "=== TrustTunnel Windows Adapter Staging Build ===" -ForegroundColor Cyan
Write-Host "Version:   $Version"
Write-Host "Arch:      $Arch"
Write-Host "BuildType: $BuildType"
Write-Host ""

# ---------------------------------------------------------------------------
# Map architecture to wintun subdirectory.
# Names follow the `build-windows` release job conventions.
# ---------------------------------------------------------------------------
switch ($Arch) {
    "x86_64" {
        $WintunSubdir = "amd64"
    }
    "aarch64" {
        $WintunSubdir = "arm64"
    }
    default {
        Write-Error "Unsupported architecture: $Arch. Use 'x86_64' or 'aarch64'."
        exit 1
    }
}

$BuildDir = Join-Path (Join-Path $PlatformDir "build") $Arch
$StagingDir = Join-Path (Join-Path $PlatformDir "staging") "trusttunnel-client-windows-$Version-$Arch"
$WintunExtractDir = Join-Path $PlatformDir "wintun"

# Read wintun version from third-party/wintun/VERSION
$WintunVersion = (Get-Content (Join-Path (Join-Path $RootDir "third-party") "wintun\VERSION")).Trim()

if ($WintunUrl -eq "") {
    $WintunUrl = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"
}

# ---------------------------------------------------------------------------
# Download and extract wintun
# ---------------------------------------------------------------------------
Write-Host "--- Downloading wintun $WintunVersion ---" -ForegroundColor Yellow
Write-Host "URL: $WintunUrl"

$wintunZip = Join-Path $PlatformDir "wintun-$WintunVersion.zip"

if (-not (Test-Path $wintunZip)) {
    Invoke-WebRequest -Uri $WintunUrl -OutFile $wintunZip
}

# Extract the ZIP. The archive contains a top-level "wintun/" directory,
# so after extraction the structure is: <WintunExtractDir>/wintun/bin/<arch>/wintun.dll
if (-not (Test-Path (Join-Path (Join-Path (Join-Path (Join-Path $WintunExtractDir "wintun") "bin") $WintunSubdir) "wintun.dll"))) {
    if (Test-Path $WintunExtractDir) {
        Remove-Item -Recurse -Force $WintunExtractDir
    }
    Expand-Archive -Force -Path $wintunZip -DestinationPath $WintunExtractDir
}

Write-Host "Wintun extracted to: $WintunExtractDir"

# ---------------------------------------------------------------------------
# Build and install
# ---------------------------------------------------------------------------
Write-Host "--- Building for $Arch ---" -ForegroundColor Yellow

# The build runs with the environment of the calling session; the
# compiler must be reachable there.
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Error "cl.exe is not on PATH. Run the script from a Visual Studio developer prompt for the target architecture."
    exit 1
}

# Create build directory
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

# CMake is configured directly rather than through the root
# CMakePresets.json: this script builds from platform/windows/ as the
# source root and stamps a per-run TT_CLIENT_VERSION into a per-arch
# install prefix, which the presets cannot express. The compiler and
# build type match the msvc-relwithdebinfo preset.
& cmake -S $PlatformDir -B $BuildDir -G Ninja `
    "-DCMAKE_BUILD_TYPE=$BuildType" `
    "-DCMAKE_C_COMPILER=cl.exe" `
    "-DCMAKE_CXX_COMPILER=cl.exe" `
    "-DTT_CLIENT_VERSION=$Version" `
    "-DCMAKE_INSTALL_PREFIX=$StagingDir"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Configure failed."
    exit 1
}

& cmake --build $BuildDir --target trusttunnel_windows trusttunnel_service trusttunnel_service_installer
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed."
    exit 1
}

& cmake --install $BuildDir
if ($LASTEXITCODE -ne 0) {
    Write-Error "Install failed."
    exit 1
}

# ---------------------------------------------------------------------------
# Add wintun.dll and its license to the staging directory
# ---------------------------------------------------------------------------
Write-Host "--- Adding wintun.dll ---" -ForegroundColor Yellow

# After extraction the path is (same convention as the wintun archive):
# <WintunExtractDir>/wintun/bin/<WintunSubdir>/wintun.dll
$wintunDll = Join-Path (Join-Path (Join-Path (Join-Path $WintunExtractDir "wintun") "bin") $WintunSubdir) "wintun.dll"
$wintunLicense = Join-Path (Join-Path $WintunExtractDir "wintun") "LICENSE.txt"

if (-not (Test-Path $wintunDll)) {
    Write-Error "wintun.dll not found at: $wintunDll"
    Write-Error "Ensure wintun was downloaded and extracted correctly."
    exit 1
}

Copy-Item -Force $wintunDll (Join-Path (Join-Path $StagingDir "bin") "wintun.dll")
Write-Host "Copied wintun.dll ($WintunSubdir)"

if (Test-Path $wintunLicense) {
    Copy-Item -Force $wintunLicense (Join-Path $StagingDir "WINTUN_LICENSE.txt")
}

Write-Host ""
Write-Host "=== Staging directory assembled ===" -ForegroundColor Green
Write-Host "Staging: $StagingDir"
Write-Host ""
Write-Host "To create the ZIP archive:"
Write-Host "  See scripts/package.ps1"
exit 0
