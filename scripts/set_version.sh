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
#   - scripts/install.sh

set -e

# Wrapper for sed in-place editing (handles macOS/Linux differences)
# macOS (BSD sed) requires -i '' for in-place without backup
# Linux (GNU sed) requires just -i
sed_i() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.2.0"
    exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-.+)?$ ]]; then
    echo "Error: Invalid version format. Expected X.Y.Z or X.Y.Z-<suffix> (e.g., 1.2.0 or 1.2.3-beta.1)"
    exit 1
fi


echo "Setting version to $VERSION"

# Android Gradle
gradle_file="platform/android/lib/build.gradle.kts"
if [ -f "$gradle_file" ]; then
    sed_i -e "s/^version = \".*\"/version = \"${VERSION}\"/" "$gradle_file"
    echo "Updated ${gradle_file}"
fi

# Apple Xcode project
pbxproj="platform/apple/TrustTunnelClient.xcodeproj/project.pbxproj"
if [ -f "$pbxproj" ]; then
    sed_i -E "s/(CURRENT_PROJECT_VERSION = )[^;]+/\1${VERSION}/" "$pbxproj"
    sed_i -E "s/(DYLIB_CURRENT_VERSION = )[^;]+/\1${VERSION}/" "$pbxproj"
    sed_i -E "s/(MARKETING_VERSION = )[^;]+/\1${VERSION}/" "$pbxproj"
    echo "Updated ${pbxproj}"
fi

# Apple CMakeLists.txt
vpn_client_cmake="platform/apple/VpnClient/CMakeLists.txt"
if [ -f "$vpn_client_cmake" ]; then
    sed_i -E "s/(^[[:space:]]+VERSION )[0-9]+\.[0-9]+\.[0-9]+(-[^[:space:]]*)?/\1${VERSION}/" "$vpn_client_cmake"
    echo "Updated ${vpn_client_cmake}"
fi

# Apple podspec
spec_file="platform/apple/TrustTunnelClient.podspec"
if [ -f "$spec_file" ]; then
    sed_i -E "s/(s\.version *= *\")[^\"]*/\1${VERSION}/" "$spec_file"
    echo "Updated ${spec_file}"
fi

# Windows resource files
# Strip pre-release suffix for numeric FILEVERSION/PRODUCTVERSION (e.g. 1,2,3,0)
VERSION_COMMAS=$(echo "${VERSION}" | sed 's/-.*//' | sed 's/\./,/g'),0
for rc_file in trusttunnel/trusttunnel_client.rc \
               trusttunnel/setup_wizard/resources/setup_wizard.rc; do
    if [ -f "$rc_file" ]; then
        sed_i -e "s/^[[:space:]]*FILEVERSION .*/    FILEVERSION ${VERSION_COMMAS}/" "$rc_file"
        sed_i -e "s/^[[:space:]]*PRODUCTVERSION .*/    PRODUCTVERSION ${VERSION_COMMAS}/" "$rc_file"
        sed_i -e "s/\(VALUE \"FileVersion\", \"\)[^\"]*/\1${VERSION}/" "$rc_file"
        sed_i -e "s/\(VALUE \"ProductVersion\", \"\)[^\"]*/\1${VERSION}/" "$rc_file"
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

# Install script
install_sh="scripts/install.sh"
if [ -f "$install_sh" ]; then
    sed_i -e "s/^version='[^']*'$/version='${VERSION}'/" "$install_sh"
    echo "Updated ${install_sh}"
fi

echo "Version set to $VERSION in all project files."
