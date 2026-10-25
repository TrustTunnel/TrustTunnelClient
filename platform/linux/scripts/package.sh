#!/usr/bin/env bash
# Package a staged TrustTunnel Linux adapter directory into a ZIP archive.
#
# Companion to build.sh: takes an assembled staging directory
# (typically staging/trusttunnel-client-linux-<version>-<arch>) and creates
# artifacts/trusttunnel-client-linux-<version>-<arch>.zip.
#
# The ZIP name is derived from the staging directory name, so the staging
# dir naming convention is part of the package contract.
#
# Usage:
#   ./package.sh --staging-dir <path-to-staging-dir>
#
# Example:
#   ./package.sh --staging-dir ../staging/trusttunnel-client-linux-1.2.3-x86_64

set -euo pipefail

STAGING_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --staging-dir)
            STAGING_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 --staging-dir <path-to-staging-dir>" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$STAGING_DIR" ]]; then
    echo "Error: --staging-dir is required" >&2
    exit 1
fi

if [[ ! -d "$STAGING_DIR/bin" ]]; then
    echo "Error: not a valid staging directory (bin/ missing): $STAGING_DIR" >&2
    exit 1
fi

STAGING_DIR="$(cd "$STAGING_DIR" && pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM_DIR="$(dirname "$SCRIPT_DIR")" # platform/linux/
ARTIFACTS_DIR="$PLATFORM_DIR/artifacts"

echo "=== TrustTunnel Linux Adapter Packaging ==="
echo "Staging: $STAGING_DIR"
echo ""

mkdir -p "$ARTIFACTS_DIR"

# The ZIP name is the staging directory name; the dir already follows the
# trusttunnel-client-linux-<version>-<arch> convention.
ZIP_NAME="$(basename "$STAGING_DIR").zip"
ZIP_PATH="$ARTIFACTS_DIR/$ZIP_NAME"

rm -f "$ZIP_PATH"
# Flat zip (files at the archive root), matching the Windows packaging contract.
# -4 deflate compression; -r recursive; -y stores symlinks as symlinks (and, without
# -X, the Unix extra fields keep the permission bits - e.g. the executable daemon)
(cd "$STAGING_DIR" && zip -q -4 -r -y "$ZIP_PATH" .)

echo ""
echo "=== Package created ==="
echo "Archive: $ZIP_PATH"
echo ""
echo "--- Archive contents ---"
unzip -l "$ZIP_PATH"
