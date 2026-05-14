#!/bin/bash

# Set version in all project files.
#
# Usage: ./scripts/set_version.sh <version>
# Example: ./scripts/set_version.sh 1.2.0
#
# This script must be run from the project root directory.
# It updates version in:
#   - platform/android/lib/build.gradle.kts
#   - platform/apple/TrustTunnelClient.xcodeproj/project.pbxproj
#   - platform/apple/VpnClient/CMakeLists.txt
#   - platform/apple/TrustTunnelClient.podspec
#   - trusttunnel/trusttunnel_client.rc
#   - trusttunnel/setup_wizard/resources/setup_wizard.rc
#   - trusttunnel/include/vpn/trusttunnel/version.h
#   - trusttunnel/setup_wizard/src/version.rs

set -e

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.2.0"
    exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Invalid version format. Expected X.Y.Z (e.g., 1.2.0)"
    exit 1
fi

echo "Setting version to $VERSION"

# Android Gradle
gradle_file="platform/android/lib/build.gradle.kts"
if [ -f "$gradle_file" ]; then
    sed -i -e "s/^version = \".*\"/version = \"${VERSION}\"/" "$gradle_file"
    echo "Updated ${gradle_file}"
fi

# Apple Xcode project
pbxproj="platform/apple/TrustTunnelClient.xcodeproj/project.pbxproj"
if [ -f "$pbxproj" ]; then
    sed -i -E "s/(CURRENT_PROJECT_VERSION = )[0-9.]+/\1${VERSION}/" "$pbxproj"
    sed -i -E "s/(DYLIB_CURRENT_VERSION = )[0-9.]+/\1${VERSION}/" "$pbxproj"
    sed -i -E "s/(MARKETING_VERSION = )[0-9.]+/\1${VERSION}/" "$pbxproj"
    echo "Updated ${pbxproj}"
fi

# Apple CMakeLists.txt
vpn_client_cmake="platform/apple/VpnClient/CMakeLists.txt"
if [ -f "$vpn_client_cmake" ]; then
    sed -i -E "s/(VERSION )[0-9]+\.[0-9]+\.[0-9]+/\1${VERSION}/" "$vpn_client_cmake"
    echo "Updated ${vpn_client_cmake}"
fi

# Apple podspec
spec_file="platform/apple/TrustTunnelClient.podspec"
if [ -f "$spec_file" ]; then
    sed -i -E "s/(s\.version *= *\")[0-9.]+/\1${VERSION}/" "$spec_file"
    echo "Updated ${spec_file}"
fi

# Windows resource files
VERSION_COMMAS=$(echo "${VERSION}" | sed 's/\./,/g'),0
for rc_file in trusttunnel/trusttunnel_client.rc \
               trusttunnel/setup_wizard/resources/setup_wizard.rc; do
    if [ -f "$rc_file" ]; then
        sed -i -e "s/^[[:space:]]*FILEVERSION .*/    FILEVERSION ${VERSION_COMMAS}/" "$rc_file"
        sed -i -e "s/^[[:space:]]*PRODUCTVERSION .*/    PRODUCTVERSION ${VERSION_COMMAS}/" "$rc_file"
        sed -i -e "s/\(VALUE \"FileVersion\", \"\)[0-9]*\.[0-9]*\.[0-9]*/\1${VERSION}/" "$rc_file"
        sed -i -e "s/\(VALUE \"ProductVersion\", \"\)[0-9]*\.[0-9]*\.[0-9]*/\1${VERSION}/" "$rc_file"
        echo "Updated ${rc_file}"
    fi
done

# C++ version header
version_h="trusttunnel/include/vpn/trusttunnel/version.h"
cat > "$version_h" << EOF
#pragma once

#define TRUSTTUNNEL_VERSION "${VERSION}"
EOF
echo "Updated ${version_h}"

# Rust version module
version_rs="trusttunnel/setup_wizard/src/version.rs"
cat > "$version_rs" << EOF
pub const VERSION: &str = "${VERSION}";
EOF
echo "Updated ${version_rs}"

echo "Version set to $VERSION in all project files."
