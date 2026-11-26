#!/bin/bash
#
# Build, Developer ID sign and stage the host app for the CLI `--sysext` mode.
#
# Used by CI; development builds are produced by `build.sh` instead. The Developer ID
# identity must be in the keychain search list and the provisioning profiles of both
# bundle ids must be installed (CI does both with the apple-devices `match-sync` action).
#
# Signing is split in two steps: the archive embeds each target's entitlements, then
# `-exportArchive` signs every bundle from its own profile listed in ExportOptions.plist.
# A single command-line signing setting cannot give the app and the system extension
# different profiles, so the per-bundle map is what routes them.
#
# Environment:
#   OUT_DIR                Directory to stage the signed app bundle into (required).
#   TT_CLIENT_VERSION      Version override; defaults to `git describe --tags --match 'v*'`.
#   MAC_TEAM_ID            Team id, TC3Q7MAJXF by default.
#   MAC_SIGNING_IDENTITY   Certificate name.

set -euo pipefail

APP_NAME="TrustTunnel CLI System Extension Manager"
APP_BUNDLE_ID="com.adguard.TrustTunnel.SystemExtensionManager"
EXTENSION_BUNDLE_ID="com.adguard.TrustTunnel.SystemExtension"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="${SCRIPT_DIR}/${APP_NAME}.xcworkspace"
BUILD_DIR="${SCRIPT_DIR}/build"

out_dir="${OUT_DIR:?OUT_DIR must be the directory to stage ${APP_NAME}.app into}"
team_id="${MAC_TEAM_ID:-TC3Q7MAJXF}"
signing_identity="${MAC_SIGNING_IDENTITY:-Developer ID Application: Adguard Software Limited (${team_id})}"
app_profile="match Direct ${APP_BUNDLE_ID} macos"
extension_profile="match Direct ${EXTENSION_BUNDLE_ID} macos"

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
    # A checkout without tags (shallow clone, exported tree) has nothing to describe;
    # `|| version=""` keeps `set -e` from aborting before the fallback below.
    version="$(git -C "${SCRIPT_DIR}" describe --tags --match 'v*' 2>/dev/null | sed -e 's/^v//')" || version=""
fi
version="${version:-0.0.0-git}"
core="$(printf '%s' "${version}" | sed -nE 's/^([0-9]+(\.[0-9]+){2}).*/\1/p')"
core="${core:-0.0.0}"

cd "${SCRIPT_DIR}"
pod install

archive="${BUILD_DIR}/${APP_NAME}.xcarchive"
export_dir="${BUILD_DIR}/export"
export_options="${BUILD_DIR}/ExportOptions.plist"
rm -rf "${archive}" "${export_dir}"

# The archive is signed without any profile: it only has to embed each target's
# entitlements into its binary, which `-exportArchive` then preserves while re-signing the
# bundle from the profile of its bundle id. $(NE_SUFFIX) in the entitlements files
# resolves to the Developer ID variant of the NetworkExtension provider values.
xcodebuild archive \
    -workspace "${WORKSPACE}" \
    -scheme "${APP_NAME}" \
    -configuration Release \
    -destination 'generic/platform=macOS' \
    -archivePath "${archive}" \
    -derivedDataPath "${BUILD_DIR}" \
    ARCHS="arm64 x86_64" \
    ONLY_ACTIVE_ARCH=NO \
    CODE_SIGN_STYLE=Manual \
    CODE_SIGN_IDENTITY="-" \
    PROVISIONING_PROFILE_SPECIFIER="" \
    NE_SUFFIX="-systemextension" \
    MARKETING_VERSION="${version}" \
    CURRENT_PROJECT_VERSION="${core}"

cat > "${export_options}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>developer-id</string>
    <key>teamID</key>
    <string>${team_id}</string>
    <key>signingStyle</key>
    <string>manual</string>
    <key>signingCertificate</key>
    <string>${signing_identity}</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>${APP_BUNDLE_ID}</key>
        <string>${app_profile}</string>
        <key>${EXTENSION_BUNDLE_ID}</key>
        <string>${extension_profile}</string>
    </dict>
</dict>
</plist>
PLIST

xcodebuild -exportArchive \
    -archivePath "${archive}" \
    -exportOptionsPlist "${export_options}" \
    -exportPath "${export_dir}"

mkdir -p "${out_dir}"
rm -rf "${out_dir}/${APP_NAME}.app"
ditto "${export_dir}/${APP_NAME}.app" "${out_dir}/${APP_NAME}.app"

echo "Staged ${out_dir}/${APP_NAME}.app"
