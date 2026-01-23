#!/bin/bash

# Version increment script for VPN Libraries
#
# Usage:
#   ./increment_version.sh                    # Auto-increment patch version
#   ./increment_version.sh 1.2.3             # Set specific version
#   ./increment_version.sh --help             # Show this help
#
# This script updates:
#   - conandata.yml (adds new version with current git hash)
#   - platform/android/lib/build.gradle.kts (updates version line)
#   - CHANGELOG.md (adds new version header)

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
  echo "Version increment script for VPN Libraries"
  echo ""
  echo "Usage:"
  echo "  $0                    # Auto-increment patch version"
  echo "  $0 1.2.3             # Set specific version"
  echo "  $0 --help            # Show this help"
  echo ""
  echo "This script updates:"
  echo "  - conandata.yml (adds new version with current git hash)"
  echo "  - platform/android/lib/build.gradle.kts (updates version line)"
  echo "  - CHANGELOG.md (adds new version header)"
  exit 0
fi

increment_version() {
  major=${1%%.*}
  minor=$(echo ${1#*.} | sed -e "s/\.[0-9]*//")
  revision=${1##*.}
  echo ${major}.${minor}.$((revision+1))
}

update_android_version() {
  local new_version=$1
  local gradle_file="platform/android/lib/build.gradle.kts"

  if [ -f "$gradle_file" ]; then
    echo "Updating Android library version to ${new_version}"
    # Update the version line in build.gradle.kts
    sed -i -e "s/^version = \".*\"/version = \"${new_version}\"/" "$gradle_file"
    echo "Updated ${gradle_file}"
  else
    echo "Warning: Android gradle file not found at ${gradle_file}"
  fi
}

update_apple_version() {
  local new_version=$1
  local old_version=$2

  pushd platform/apple/
    local pbxproj_file="TrustTunnelClient.xcodeproj/project.pbxproj"
    sed -i -e "s/CURRENT_PROJECT_VERSION = ${old_version}/CURRENT_PROJECT_VERSION = ${new_version}/" ${pbxproj_file}
    sed -i -e "s/DYLIB_CURRENT_VERSION = ${old_version}/DYLIB_CURRENT_VERSION = ${new_version}/" ${pbxproj_file}
    sed -i -e "s/MARKETING_VERSION = ${old_version}/MARKETING_VERSION = ${new_version}/" ${pbxproj_file}

    local vpn_client_cmake="VpnClient/CMakeLists.txt"
    local old_part="VERSION ${old_version}"
    local new_part="VERSION ${new_version}"
    sed -i -e "s/${old_part}/${new_part}/" "${vpn_client_cmake}"

    local spec_file="TrustTunnelClient.podspec"
    local old_part="s.version      = \"${old_version}\""
    local new_part="s.version      = \"${new_version}\""
    sed -i -e "s/${old_part}/${new_part}/" "${spec_file}"
  popd
}

update_trusttunnel_windows_rc_versions() {
  local new_version=$1
  local rc_file=$2

  if [ -f "$rc_file" ]; then
    echo "Updating Windows rc version in ${rc_file} to ${new_version}"

    local version_commas
    version_commas=$(echo "${new_version}" | sed 's/\./,/g'),0

    sed -i -e "s/^[[:space:]]*FILEVERSION .*/    FILEVERSION ${version_commas}/" "$rc_file"
    sed -i -e "s/^[[:space:]]*PRODUCTVERSION .*/    PRODUCTVERSION ${version_commas}/" "$rc_file"

    sed -i -e "s/\(VALUE \"FileVersion\", \"\)[0-9]*\.[0-9]*\.[0-9]*\(\"\)/\1${new_version}\2/" "$rc_file"
    sed -i -e "s/\(VALUE \"ProductVersion\", \"\)[0-9]*\.[0-9]*\.[0-9]*\(\"\)/\1${new_version}\2/" "$rc_file"
  else
    echo "Warning: TrustTunnel Windows rc file not found at ${rc_file}"
  fi
}

argument_version=$1
if [ -z "$argument_version" ]
then
  VERSION=$(cat conandata.yml | grep "[0-9]*\.[0-9]*." | tail -1 | sed "s/\"//" | sed "s/\"\://" | sed "s/ //g")
  echo "Last version was ${VERSION}"
  NEW_VERSION=$(increment_version ${VERSION})
  echo "New version is ${NEW_VERSION}"
else
  if [[ "$argument_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
  then
    NEW_VERSION=$1
    echo "New version is ${NEW_VERSION}"
  else
    echo "INVALID VERSION FORMAT"
    exit 1
  fi
fi

if [ -z "$NEW_VERSION" ]; then
  echo "No version to update"
  exit 1
fi

COMMIT_HASH=$(git rev-parse HEAD)
echo "Last commit hash is ${COMMIT_HASH}"

# Update conandata.yml
printf "  \"${NEW_VERSION}\":\n    hash: \"${COMMIT_HASH}\"\n" | tee -a conandata.yml

# Update Android library version
update_android_version "${NEW_VERSION}"

update_apple_version "${NEW_VERSION}" "${VERSION}"

# Update TrustTunnel Windows resources versions
update_trusttunnel_windows_rc_versions "${NEW_VERSION}" "trusttunnel/trusttunnel_client.rc"
update_trusttunnel_windows_rc_versions "${NEW_VERSION}" "trusttunnel/setup_wizard/resources/setup_wizard.rc"

# Update changelog
sed -i -e '3{s/##/##/;t;s/^/## '${NEW_VERSION}'\n\n/}' CHANGELOG.md

echo "Version increment completed successfully!"
echo "Updated files:"
echo "  - conandata.yml"
echo "  - platform/android/lib/build.gradle.kts"
echo "  - platform/apple/VpnClient/CMakeLists.txt"
echo "  - platform/apple/TrustTunnelClient.xcodeproj/project.pbxproj"
echo "  - platform/apple/TrustTunnelClient.podspec"
echo "  - trusttunnel/trusttunnel_client.rc"
echo "  - trusttunnel/setup_wizard/resources/setup_wizard.rc"
echo "  - CHANGELOG.md"
