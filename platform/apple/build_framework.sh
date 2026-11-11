set -xe

CONFIGURATION="Release"
if [[ "$1" == "-debug" ]]; then
  CONFIGURATION="Debug"
fi

# Resolve the version once: TT_CLIENT_VERSION env -> git describe --tags
# --match v* -> 0.0.0-git. Exported so `pod install` (the podspec resolver) and
# the CMake-driven VpnClientFramework build pick it up; the numeric core is
# passed to xcodebuild as build-setting overrides (the Mach-O / Info.plist
# version fields must be numeric), so no source file is patched.
if [[ -n "${TT_CLIENT_VERSION:-}" ]]; then
  VER_FULL="${TT_CLIENT_VERSION}"
else
  VER_FULL="$(git describe --tags --match 'v*' 2>/dev/null | sed -e 's/^v//')"
  [[ -z "${VER_FULL}" ]] && VER_FULL="0.0.0-git"
fi
VER_CORE="$(printf '%s' "${VER_FULL}" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')"
[[ "${VER_CORE}" == "${VER_FULL}" && ! "${VER_FULL}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && VER_CORE="0.0.0"
export TT_CLIENT_VERSION="${VER_FULL}"

VERSION_ARGS=(MARKETING_VERSION="${VER_FULL}" CURRENT_PROJECT_VERSION="${VER_CORE}" DYLIB_CURRENT_VERSION="${VER_CORE}")

rm -rf build

pod install

# Build VpnClientFramework
xcodebuild -project TrustTunnelClient.xcodeproj \
  -scheme VpnClientFramework \
  -configuration $CONFIGURATION \
  "${VERSION_ARGS[@]}"

rm -rf Framework
mkdir -p Framework
mv build/framework/VpnClientFramework.xcframework Framework/

# Build VpnManager framework
xcodebuild -workspace TrustTunnelClient.xcworkspace \
  -scheme TrustTunnelClient-iOS \
  -configuration $CONFIGURATION \
  -sdk iphoneos \
  -archivePath ./build/ios.xcarchive \
  "${VERSION_ARGS[@]}" \
  archive

# Build VpnManager framework
xcodebuild -workspace TrustTunnelClient.xcworkspace \
  -scheme TrustTunnelClient-iOS \
  -configuration $CONFIGURATION \
  -sdk iphonesimulator \
  -archivePath ./build/iphonesimulator.xcarchive \
  ARCHS="x86_64 arm64" \
  ONLY_ACTIVE_ARCH=NO \
  "${VERSION_ARGS[@]}" \
  archive

# Build VpnManager framework
xcodebuild -workspace TrustTunnelClient.xcworkspace \
  -scheme TrustTunnelClient-MacOS \
  -configuration $CONFIGURATION \
  -archivePath ./build/macos.xcarchive \
  ARCHS="x86_64 arm64" \
  ONLY_ACTIVE_ARCH=NO \
  "${VERSION_ARGS[@]}" \
  archive


xcodebuild -create-xcframework \
  -framework ./build/ios.xcarchive/Products/Library/Frameworks/TrustTunnelClient.framework \
  -framework ./build/iphonesimulator.xcarchive/Products/Library/Frameworks/TrustTunnelClient.framework \
  -framework ./build/macos.xcarchive/Products/Library/Frameworks/TrustTunnelClient.framework \
  -output Framework/TrustTunnelClient.xcframework
