# Build and package the TrustTunnel Windows adapter for distribution.
#
# Usage:
#   .\build_package.ps1 [-Version <semver>] [-Arch <amd64|arm64>] [-BuildType <RelWithDebInfo|Release|Debug>] [-SkipBuild] [-SkipWintun] [-WintunUrl <url>]
#
# Examples:
#   .\build_package.ps1                        # Build amd64 RelWithDebInfo, version from git tag
#   .\build_package.ps1 -Arch arm64            # Build arm64
#   .\build_package.ps1 -Version 1.2.3         # Override version
#   .\build_package.ps1 -SkipBuild             # Skip build, only package existing artifacts
#   .\build_package.ps1 -WintunUrl "https://artifactory.example.com/wintun-0.14.1.zip"
#
# Output:
#   artifacts/trusttunnel-client-windows-<arch>-<version>.zip

param(
    [string]$Version = "",
    [string]$Arch = "amd64",
    [string]$BuildType = "RelWithDebInfo",
    [switch]$SkipBuild = $false,
    [switch]$SkipWintun = $false,
    [string]$WintunUrl = ""
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Resolve version
# ---------------------------------------------------------------------------
if ($Version -eq "") {
    $gitTag = git describe --tags --exact-match 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitTag -match '^\d+\.\d+\.\d+') {
        $Version = $gitTag
    } else {
        $gitDesc = git describe --tags --always --dirty 2>$null
        if ($LASTEXITCODE -eq 0) {
            $Version = $gitDesc -replace '^v', ''
        } else {
            $Version = "0.0.0-dev"
        }
    }
}

Write-Host "=== TrustTunnel Windows Adapter Package Build ===" -ForegroundColor Cyan
Write-Host "Version:    $Version"
Write-Host "Arch:       $Arch"
Write-Host "BuildType:  $BuildType"
Write-Host ""

# ---------------------------------------------------------------------------
# Map architecture to MSVC toolset and wintun subdirectory
# ---------------------------------------------------------------------------
switch ($Arch) {
    "amd64" {
        $VcvarsArch = "x64"
        $WintunSubdir = "amd64"
    }
    "arm64" {
        $VcvarsArch = "arm64"
        $WintunSubdir = "arm64"
    }
    default {
        Write-Error "Unsupported architecture: $Arch. Use 'amd64' or 'arm64'."
        exit 1
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PlatformDir = Split-Path -Parent $ScriptDir   # platform/windows/
$RootDir = Split-Path -Parent (Split-Path -Parent $PlatformDir) # repo root
$BuildDir = Join-Path $PlatformDir "build" $Arch
$StagingDir = Join-Path $PlatformDir "staging" "trusttunnel-client-windows-$Arch-$Version"
$ArtifactsDir = Join-Path $PlatformDir "artifacts"
$WintunExtractDir = Join-Path $PlatformDir "wintun"

# Read wintun version from third-party/wintun/VERSION
$WintunVersion = (Get-Content (Join-Path $RootDir "third-party" "wintun" "VERSION")).Trim()

if ($WintunUrl -eq "") {
    $WintunUrl = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"
}

# ---------------------------------------------------------------------------
# Download and extract wintun
# ---------------------------------------------------------------------------
if (-not $SkipWintun) {
    Write-Host "--- Downloading wintun $WintunVersion ---" -ForegroundColor Yellow
    Write-Host "URL: $WintunUrl"

    $wintunZip = Join-Path $PlatformDir "wintun-$WintunVersion.zip"

    if (-not (Test-Path $wintunZip)) {
        Invoke-WebRequest -Uri $WintunUrl -OutFile $wintunZip
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to download wintun from: $WintunUrl"
            exit 1
        }
    }

    # Extract the ZIP. The archive contains a top-level "wintun/" directory,
    # so after extraction the structure is: <WintunExtractDir>/wintun/bin/<arch>/wintun.dll
    if (-not (Test-Path (Join-Path $WintunExtractDir "wintun" "bin" $WintunSubdir "wintun.dll"))) {
        if (Test-Path $WintunExtractDir) {
            Remove-Item -Recurse -Force $WintunExtractDir
        }
        Expand-Archive -Force -Path $wintunZip -DestinationPath $WintunExtractDir
    }

    Write-Host "Wintun extracted to: $WintunExtractDir"
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
if (-not $SkipBuild) {
    Write-Host "--- Building for $Arch ---" -ForegroundColor Yellow

    # Find vcvarsall.bat
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vsWhere)) {
        Write-Error "vswhere.exe not found. Is Visual Studio installed?"
        exit 1
    }

    $vsInstallPath = & $vsWhere -latest -property installationPath 2>$null
    if (-not $vsInstallPath) {
        Write-Error "Could not find Visual Studio installation."
        exit 1
    }

    $vcvarsall = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvarsall.bat"
    if (-not (Test-Path $vcvarsall)) {
        Write-Error "vcvarsall.bat not found at: $vcvarsall"
        exit 1
    }

    # Create build directory
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

    # Configure and build using vcvarsall environment
    $buildScript = @"
@echo off
call "$vcvarsall" $VcvarsArch
cd /d "$BuildDir"
cmake -S "$PlatformDir" -B "$BuildDir" -G Ninja ^
    -DCMAKE_BUILD_TYPE=$BuildType ^
    -DCMAKE_C_COMPILER=cl.exe ^
    -DCMAKE_CXX_COMPILER=cl.exe ^
    -DCMAKE_INSTALL_PREFIX="$StagingDir"
if %errorlevel% neq 0 exit /b %errorlevel%
cmake --build "$BuildDir" --target vpn_easy vpn_easy_service service_installer
if %errorlevel% neq 0 exit /b %errorlevel%
cmake --install "$BuildDir"
if %errorlevel% neq 0 exit /b %errorlevel%
"@

    $batFile = Join-Path $BuildDir "_build.bat"
    Set-Content -Path $batFile -Value $buildScript

    cmd /c $batFile
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed."
        exit 1
    }

    Write-Host "--- Build succeeded ---" -ForegroundColor Green
} else {
    # When skipping build, still need to install from existing build dir
    Write-Host "--- Skipping build, running install ---" -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    cmake --install "$BuildDir" --prefix "$StagingDir"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Install failed. Make sure the project has been built."
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Add wintun.dll to the staging directory
# ---------------------------------------------------------------------------
if (-not $SkipWintun) {
    Write-Host "--- Adding wintun.dll ---" -ForegroundColor Yellow

    # After extraction the path follows the same convention as deploy_cli.yaml:
    # <WintunExtractDir>/wintun/bin/<WintunSubdir>/wintun.dll
    $wintunDll = Join-Path $WintunExtractDir "wintun" "bin" $WintunSubdir "wintun.dll"
    $wintunLicense = Join-Path $WintunExtractDir "wintun" "LICENSE.txt"

    if (-not (Test-Path $wintunDll)) {
        Write-Error "wintun.dll not found at: $wintunDll"
        Write-Error "Ensure wintun was downloaded and extracted correctly."
        exit 1
    }

    Copy-Item -Force $wintunDll (Join-Path $StagingDir "bin" "wintun.dll")
    Write-Host "Copied wintun.dll ($WintunSubdir)"

    if (Test-Path $wintunLicense) {
        Copy-Item -Force $wintunLicense (Join-Path $StagingDir "WINTUN_LICENSE.txt")
    }
}

# ---------------------------------------------------------------------------
# Create ZIP archive
# ---------------------------------------------------------------------------
Write-Host "--- Creating ZIP archive ---" -ForegroundColor Yellow

New-Item -ItemType Directory -Force -Path $ArtifactsDir | Out-Null

$zipName = "trusttunnel-client-windows-$Arch-$Version.zip"
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
