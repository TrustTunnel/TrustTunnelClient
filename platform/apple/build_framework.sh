#!/bin/bash
#
# Build the Apple frameworks consumed by the platform adapters and by the CLI macOS
# system extension host app: TrustTunnelClient.xcframework (iOS device, iOS simulator and
# macOS slices) and VpnClientFramework.xcframework (built by VpnClient/build_client.sh).
#
# Usage: build_framework.sh [-debug] [-macos-only]
#   -debug       build the Debug configuration
#   -macos-only  build only the macOS slices, skipping the two iOS archives
#
# Both frameworks are always written to Framework/, which is the path the podspec
# vendors, so Framework/ ends up with the slices of the platforms this run built.

set -xe

CONFIGURATION="Release"
MACOS_ONLY=false
while [ $# -gt 0 ]; do
  case "$1" in
  -debug) CONFIGURATION="Debug" ;;
  -macos-only) MACOS_ONLY=true ;;
  *)
    echo "usage: $0 [-debug] [-macos-only]" >&2
    exit 1
    ;;
  esac
  shift
done

# Resolve the version once: TT_CLIENT_VERSION env -> git describe --tags
# --match v* -> 0.0.0-git. Exported so `pod install` (the podspec resolver) and
# the CMake-driven VpnClientFramework build pick it up; the numeric core is
# passed to xcodebuild as build-setting overrides (the Mach-O / Info.plist
# version fields must be numeric), so no source file is patched.
if [ -n "${TT_CLIENT_VERSION:-}" ]; then
  VER_FULL="${TT_CLIENT_VERSION}"
else
  VER_FULL="$(git describe --tags --match 'v*' 2>/dev/null | sed -e 's/^v//')"
  [ -z "${VER_FULL}" ] && VER_FULL="0.0.0-git"
fi
VER_CORE="$(printf '%s' "${VER_FULL}" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')"
if [ "${VER_CORE}" == "${VER_FULL}" ] && ! [[ "${VER_FULL}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  VER_CORE="0.0.0"
fi
export TT_CLIENT_VERSION="${VER_FULL}"

VERSION_ARGS=(MARKETING_VERSION="${VER_FULL}" CURRENT_PROJECT_VERSION="${VER_CORE}" DYLIB_CURRENT_VERSION="${VER_CORE}")

# xcodebuild refuses to overwrite an existing archive and -create-xcframework an existing
# framework, so only this run's products are removed. The CMake/ninja trees are reused and
# rebuild incrementally, including after switching the configuration.
ARCHIVES=./build/archives
mkdir -p "${ARCHIVES}"
rm -rf "${ARCHIVES}/macos.xcarchive" Framework
if [ "${MACOS_ONLY}" != true ]; then
  rm -rf "${ARCHIVES}/ios.xcarchive" "${ARCHIVES}/iphonesimulator.xcarchive"
fi

pod install

# The macOS-only run restricts the core framework build to the macOS slices; the full run
# leaves TARGET_OSES unset, which VpnClient/build_client.sh treats as all platforms. The
# value is inherited by that script, which runs as a build phase of the
# VpnClientFramework target.
if [ "${MACOS_ONLY}" = true ]; then
  export TARGET_OSES="${TARGET_OSES:-macos-x86_64,macos-arm64}"
fi

# Build VpnClientFramework
xcodebuild -project TrustTunnelClient.xcodeproj \
  -scheme VpnClientFramework \
  -configuration $CONFIGURATION \
  "${VERSION_ARGS[@]}"

mkdir -p Framework
mv build/framework/VpnClientFramework.xcframework Framework/

if [ "${MACOS_ONLY}" = true ]; then
  # Build VpnManager framework for macOS
  xcodebuild -workspace TrustTunnelClient.xcworkspace \
    -scheme TrustTunnelClient-MacOS \
    -configuration $CONFIGURATION \
    -archivePath ${ARCHIVES}/macos.xcarchive \
    ARCHS="x86_64 arm64" \
    ONLY_ACTIVE_ARCH=NO \
    "${VERSION_ARGS[@]}" \
    archive
else
  # Build VpnManager framework for iOS
  xcodebuild -workspace TrustTunnelClient.xcworkspace \
    -scheme TrustTunnelClient-iOS \
    -configuration $CONFIGURATION \
    -sdk iphoneos \
    -archivePath ${ARCHIVES}/ios.xcarchive \
    "${VERSION_ARGS[@]}" \
    archive

  # Build VpnManager framework for the iOS simulator
  xcodebuild -workspace TrustTunnelClient.xcworkspace \
    -scheme TrustTunnelClient-iOS \
    -configuration $CONFIGURATION \
    -sdk iphonesimulator \
    -archivePath ${ARCHIVES}/iphonesimulator.xcarchive \
    ARCHS="x86_64 arm64" \
    ONLY_ACTIVE_ARCH=NO \
    "${VERSION_ARGS[@]}" \
    archive

  # Build VpnManager framework for macOS
  xcodebuild -workspace TrustTunnelClient.xcworkspace \
    -scheme TrustTunnelClient-MacOS \
    -configuration $CONFIGURATION \
    -archivePath ${ARCHIVES}/macos.xcarchive \
    ARCHS="x86_64 arm64" \
    ONLY_ACTIVE_ARCH=NO \
    "${VERSION_ARGS[@]}" \
    archive
fi

# Assemble the xcframework from the slices this run built.
XC_ARGS=()
for platform in ios iphonesimulator macos; do
  FRAMEWORK="${ARCHIVES}/${platform}.xcarchive/Products/Library/Frameworks/TrustTunnelClient.framework"
  if [ -d "${FRAMEWORK}" ]; then
    XC_ARGS+=(-framework "${FRAMEWORK}")
  fi
done

xcodebuild -create-xcframework "${XC_ARGS[@]}" \
  -output Framework/TrustTunnelClient.xcframework
