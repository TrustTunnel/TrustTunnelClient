# TrustTunnel Windows VPN Adapter

Easy wrapper for the TrustTunnel VPN API — essentially `trusttunnel_client` as a library with two operations: `start` (takes TOML config) and `stop`.

**Runtime requirements:**

- `wintun.dll` (matching architecture) must be in the DLL search path
- Administrator privileges (for tunnel listener)

## Building

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --target vpn_easy vpn_easy_service service_installer
```

## Distribution Package

Architecture names match the `build-windows` release job: `x86_64`, `i686`, `aarch64`.

`-Version` is required — pass the exact version you intend to build.

```powershell
# Build ZIP for x86_64 (default arch)
./scripts/build_package.ps1 -Version 1.2.3

# Build for aarch64 / use internal wintun mirror
./scripts/build_package.ps1 -Version 1.2.3 -Arch aarch64 -WintunUrl "https://artifactory.example.com/binaries/wintun-0.14.1.zip"

# Build 32-bit x86
./scripts/build_package.ps1 -Version 1.2.3 -Arch i686
```

Output: `artifacts/trusttunnel-client-windows-<arch>-<version>.zip`

### Package Structure

```text
trusttunnel-client-windows-x86_64-1.1.3/
├── include/vpn/          # vpn_easy.h, vpn_easy_service.h, platform.h
├── lib/                  # vpn_easy.lib + CMake config
├── bin/                  # vpn_easy.dll, vpn_easy_service.exe, service_installer.exe, wintun.dll
└── WINTUN_LICENSE.txt
```

`vpn_easy.dll` contains all transitive dependencies — the consumer needs only `vpn_easy.lib` at link time and `vpn_easy.dll` at runtime.

## Consuming via FetchContent

Add this to your app's `CMakeLists.txt` (e.g. `windows/runner/CMakeLists.txt` for Flutter):

```cmake
include(FetchContent)

set(TRUSTTUNNEL_VERSION "1.1.3")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
    set(TRUSTTUNNEL_ARCH "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
    set(TRUSTTUNNEL_ARCH "aarch64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "X86|x86|i686")
    set(TRUSTTUNNEL_ARCH "i686")
endif()

# For Maven: use the GitHub Packages URL below.
# For local testing: point at the local ZIP instead, e.g.:
#   set(TRUSTTUNNEL_URL "file:///C:/Dev/vpn-libs/platform/windows/artifacts/trusttunnel-client-windows-${TRUSTTUNNEL_ARCH}-${TRUSTTUNNEL_VERSION}.zip")
set(TRUSTTUNNEL_URL "https://maven.pkg.github.com/TrustTunnel/TrustTunnelClient/com/adguard/trusttunnel/trusttunnel-client-windows-${TRUSTTUNNEL_ARCH}/${TRUSTTUNNEL_VERSION}/trusttunnel-client-windows-${TRUSTTUNNEL_ARCH}-${TRUSTTUNNEL_VERSION}.zip")

FetchContent_Declare(
    TrustTunnelClientWindows
    URL "${TRUSTTUNNEL_URL}"
    URL_HASH "SHA256=<expected-hash>"  # Recommended
)
FetchContent_MakeAvailable(TrustTunnelClientWindows)

# The archive ships lib/cmake/TrustTunnelClientWindows/TrustTunnelClientWindowsConfig.cmake
# Register that location so find_package() can discover it.
list(APPEND CMAKE_PREFIX_PATH "${trusttunnelclientwindows_SOURCE_DIR}")

find_package(TrustTunnelClientWindows REQUIRED)

target_link_libraries(${BINARY_NAME} PRIVATE TrustTunnelClientWindows::vpn_easy)
add_dependencies(${BINARY_NAME} TrustTunnelClientWindows::vpn_easy_service TrustTunnelClientWindows::service_installer)
```

To switch between Maven and local testing, only change `TRUSTTUNNEL_URL`.

### Deploying Runtime Binaries

`vpn_easy.dll`, `vpn_easy_service.exe`, `service_installer.exe`, and `wintun.dll` must be next to the app executable at runtime. Copy them as a post-build step:

```cmake
set(_TT_BIN_DIR "${trusttunnelclientwindows_SOURCE_DIR}/bin")
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_TT_BIN_DIR}/vpn_easy.dll" $<TARGET_FILE_DIR:${BINARY_NAME}>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_TT_BIN_DIR}/vpn_easy_service.exe" $<TARGET_FILE_DIR:${BINARY_NAME}>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_TT_BIN_DIR}/service_installer.exe" $<TARGET_FILE_DIR:${BINARY_NAME}>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_TT_BIN_DIR}/wintun.dll" $<TARGET_FILE_DIR:${BINARY_NAME}>
)
```

## Publishing to GitHub Maven Packages

```powershell
$env:TOKEN = "ghp_..."  # PAT with write:packages scope

./scripts/publish_maven.ps1 -Version 1.1.3 -Arch x86_64
./scripts/publish_maven.ps1 -Version 1.1.3 -Arch i686
./scripts/publish_maven.ps1 -Version 1.1.3 -Arch aarch64
```
