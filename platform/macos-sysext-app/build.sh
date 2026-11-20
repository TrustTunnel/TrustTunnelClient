#!/bin/bash
#
# Build the host app for the CLI `--sysext` mode and stage it next to the CLI binary.
#
# Development builds use the project's automatic signing (the team is set in the Xcode
# project). Release builds are produced by `package.sh` instead.
#
# Environment:
#   OUT_DIR            Directory to stage the app bundle into (required). In the CMake
#                      build tree the CLI binary lives in <build dir>/trusttunnel.
#   CONFIGURATION      Xcode configuration, Debug by default.
#   TT_CLIENT_VERSION  Version override; defaults to `git describe --tags --match 'v*'`.
#
# The TrustTunnelClient pod links the prebuilt xcframeworks from platform/apple, so
# platform/apple/build_framework.sh must have been run at least once.

set -euo pipefail

APP_NAME="TrustTunnel CLI System Extension Manager"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="${SCRIPT_DIR}/${APP_NAME}.xcworkspace"
BUILD_DIR="${SCRIPT_DIR}/build"

out_dir="${OUT_DIR:?OUT_DIR must be the directory to stage ${APP_NAME}.app into}"
configuration="${CONFIGURATION:-Debug}"

# The build runs from this directory, so make the output path absolute first.
mkdir -p "${out_dir}"
out_dir="$(cd "${out_dir}" && pwd)"

for framework in TrustTunnelClient VpnClientFramework; do
    if [ ! -d "${SCRIPT_DIR}/../apple/Framework/${framework}.xcframework" ]; then
        echo "Missing ${framework}.xcframework, run platform/apple/build_framework.sh first" >&2
        exit 1
    fi
done

version="${TT_CLIENT_VERSION:-}"
if [ -z "${version}" ]; then
    version="$(git -C "${SCRIPT_DIR}" describe --tags --match 'v*' 2>/dev/null | sed -e 's/^v//')"
fi
version="${version:-0.0.0-git}"
core="$(printf '%s' "${version}" | sed -nE 's/^([0-9]+(\.[0-9]+){2}).*/\1/p')"
core="${core:-0.0.0}"

cd "${SCRIPT_DIR}"
pod install

xcodebuild build \
    -workspace "${WORKSPACE}" \
    -scheme "${APP_NAME}" \
    -configuration "${configuration}" \
    -destination 'platform=macOS' \
    -derivedDataPath "${BUILD_DIR}" \
    MARKETING_VERSION="${version}" \
    CURRENT_PROJECT_VERSION="${core}"

mkdir -p "${out_dir}"
rm -rf "${out_dir}/${APP_NAME}.app"
ditto "${BUILD_DIR}/Build/Products/${configuration}/${APP_NAME}.app" "${out_dir}/${APP_NAME}.app"

echo "Staged ${out_dir}/${APP_NAME}.app"
