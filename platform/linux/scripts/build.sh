#!/usr/bin/env bash
# Build and stage the TrustTunnel Linux adapter for packaging.
#
# Companion to package.sh: assembles a complete, self-contained staging directory at
# staging/trusttunnel-client-linux-<version>-<arch>/ (daemon, static libraries, headers,
# CMake package config). Zipping happens separately (see package.sh).
#
# Architecture names match the Windows release conventions: x86_64, aarch64.
#
# Usage:
#   ./build.sh --version <semver> [--arch <x86_64|aarch64>] [--build-type <type>]
#
# Examples:
#   ./build.sh --version 1.2.3                       # Build x86_64 RelWithDebInfo
#   ./build.sh --version 1.2.3 --arch aarch64        # Build aarch64
#
# Requirements: clang, cmake, ninja, cargo (for the deeplink library) and the Conan
# dependencies (run `make bootstrap_deps` once, or let the conan bootstrap do it -
# the script also honours SKIP_BOOTSTRAP=1 like `make`).

set -euo pipefail

VERSION=""
ARCH="x86_64"
BUILD_TYPE="RelWithDebInfo"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --build-type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 --version <semver> [--arch <x86_64|aarch64>] [--build-type <type>]" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "Error: --version is required" >&2
    exit 1
fi

case "$ARCH" in
    x86_64) ;;
    aarch64) ;;
    *)
        echo "Error: unsupported architecture: $ARCH. Use 'x86_64' or 'aarch64'." >&2
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM_DIR="$(dirname "$SCRIPT_DIR")" # platform/linux/
ROOT_DIR="$(cd "$PLATFORM_DIR/../.." && pwd)"

STAGING_DIR="$PLATFORM_DIR/staging/trusttunnel-client-linux-$VERSION-$ARCH"
BUILD_DIR="$PLATFORM_DIR/build/$ARCH"

echo "=== TrustTunnel Linux Adapter Staging Build ==="
echo "Version:   $VERSION"
echo "Arch:      $ARCH"
echo "BuildType: $BUILD_TYPE"
echo ""

for tool in cmake ninja clang clang++; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: $tool is not on PATH" >&2
        exit 1
    fi
done
if ! command -v cargo >/dev/null 2>&1; then
    echo "Warning: cargo is not on PATH - the deeplink library will not be built" >&2
fi

# Conan bootstrap: like `make`, rely on a prepared local cache unless the caller
# provides SKIP_BOOTSTRAP=1 (CI images ship the dependencies preinstalled).
if [[ "${SKIP_BOOTSTRAP:-0}" != "1" && ! -d "$HOME/.conan2" ]]; then
    echo "--- Bootstrapping Conan dependencies ---"
    (cd "$ROOT_DIR" && make bootstrap_deps)
fi

mkdir -p "$BUILD_DIR"

# CMake is configured directly rather than through the root CMakePresets.json: this
# script builds from platform/linux/ as the source root and stamps a per-run
# TT_CLIENT_VERSION into a per-arch install prefix, which the presets cannot express.
cmake -S "$PLATFORM_DIR" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DTT_CLIENT_VERSION="$VERSION" \
    -DCMAKE_INSTALL_PREFIX="$STAGING_DIR"

cmake --build "$BUILD_DIR"
# --strip drops debug symbols from the installed binaries (the RelWithDebInfo
# binaries carry them; the archive is a release artifact)
cmake --install "$BUILD_DIR" --strip

echo ""
echo "=== Staging directory assembled ==="
echo "Staging: $STAGING_DIR"
echo ""
echo "To create the ZIP archive:"
echo "  See scripts/package.sh"
