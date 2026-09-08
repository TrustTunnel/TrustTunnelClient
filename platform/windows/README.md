# TrustTunnel Windows VPN Adapter

Easy wrapper for the TrustTunnel VPN API — essentially `trusttunnel_client` as a library with two operations: `start` (takes TOML config) and `stop`.

**Runtime requirements:**

- `wintun.dll` (matching architecture) must be in the DLL search path
- Administrator privileges (for tunnel listener)

## Building

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --target trusttunnel_windows trusttunnel_service trusttunnel_service_installer
```

## Distribution Package

Architecture names match the `deploy-windows` release job: `x86_64`, `aarch64`.

`-Version` is required — pass the exact version you intend to build.

Packaging is split into stages:

- `build.ps1` — build and assemble a complete staging directory at
  `staging/trusttunnel-client-windows-<version>-<arch>/` (headers, import
  lib, binaries, `wintun.dll`, licenses)
- `package.ps1` — zip a staging directory (e.g. after signing) into
  `artifacts/trusttunnel-client-windows-<version>-<arch>.zip`
- `publish_maven.ps1` — upload the zip to GitHub Maven Packages

`build_and_package.ps1` composes the both and acts as oneshot for local builds;

`build.ps1` and `build_and_package.ps1` build with the MSVC environment of the session they run in.
Run them from a Visual Studio developer prompt for the target architecture — the
`x64 Native Tools Command Prompt` (or `Developer PowerShell`) for `x86_64`,
the `x64 ARM64 Cross Tools Command Prompt` for `aarch64` — launching `pwsh`
inside the prompt first if needed.

```powershell
# Build ZIP for x86_64 (default arch)
./scripts/build_and_package.ps1 -Version 1.2.3

# Build for aarch64 / use internal wintun mirror
./scripts/build_and_package.ps1 -Version 1.2.3 -Arch aarch64 -WintunUrl "https://artifactory.example.com/binaries/wintun-0.14.1.zip"
```

Output: `artifacts/trusttunnel-client-windows-<version>-<arch>.zip`

Note: packages built locally are **unsigned**.

### Package Structure

```text
trusttunnel-client-windows-1.1.3-x86_64/
├── include/trusttunnel/  # trusttunnel.h, trusttunnel_service.h
├── include/vpn/          # platform.h
├── lib/                  # trusttunnel.lib + CMake config
├── bin/                  # trusttunnel.dll, trusttunnel_service.exe, trusttunnel_service_installer.exe, wintun.dll
└── WINTUN_LICENSE.txt
```

`trusttunnel.dll` contains all transitive dependencies — the consumer needs only `trusttunnel.lib` at link time and `trusttunnel.dll` at runtime.

## Consuming via FetchContent

Add this to your app's `CMakeLists.txt` (e.g. `windows/runner/CMakeLists.txt` for Flutter):

```cmake
include(FetchContent)

set(TRUSTTUNNEL_VERSION "1.1.3")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
    set(TRUSTTUNNEL_ARCH "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
    set(TRUSTTUNNEL_ARCH "aarch64")
endif()

# For Maven: use the GitHub Packages URL below.
# For local testing: point at the local ZIP instead, e.g.:
#   set(TRUSTTUNNEL_URL "file:///C:/Dev/vpn-libs/platform/windows/artifacts/trusttunnel-client-windows-${TRUSTTUNNEL_VERSION}-${TRUSTTUNNEL_ARCH}.zip")
set(TRUSTTUNNEL_URL "https://maven.pkg.github.com/TrustTunnel/TrustTunnelClient/com/adguard/trusttunnel/trusttunnel-client-windows/${TRUSTTUNNEL_VERSION}/trusttunnel-client-windows-${TRUSTTUNNEL_VERSION}-${TRUSTTUNNEL_ARCH}.zip")

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

target_link_libraries(${BINARY_NAME} PRIVATE TrustTunnelClientWindows::trusttunnel)
add_dependencies(${BINARY_NAME} TrustTunnelClientWindows::trusttunnel_service TrustTunnelClientWindows::trusttunnel_service_installer)
```

To switch between Maven and local testing, only change `TRUSTTUNNEL_URL`.

### Deploying Runtime Binaries

`trusttunnel.dll`, `trusttunnel_service.exe`, `trusttunnel_service_installer.exe`, and `wintun.dll` must be next to the app executable at runtime. Copy them as a post-build step:

```cmake
set(_TT_BIN_DIR "${trusttunnelclientwindows_SOURCE_DIR}/bin")
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_TT_BIN_DIR}/trusttunnel.dll" $<TARGET_FILE_DIR:${BINARY_NAME}>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_TT_BIN_DIR}/trusttunnel_service.exe" $<TARGET_FILE_DIR:${BINARY_NAME}>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_TT_BIN_DIR}/trusttunnel_service_installer.exe" $<TARGET_FILE_DIR:${BINARY_NAME}>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_TT_BIN_DIR}/wintun.dll" $<TARGET_FILE_DIR:${BINARY_NAME}>
)
```

## Publishing to GitHub Maven Packages

```powershell
$env:TOKEN = "ghp_..."  # PAT with write:packages scope

./scripts/publish_maven.ps1 -Version 1.1.3 -Arch x86_64
./scripts/publish_maven.ps1 -Version 1.1.3 -Arch aarch64
```
