# TrustTunnel Windows VPN Adapter

Easy wrapper for the TrustTunnel VPN API.

- Basically, the `trusttunnel_client` command line application in the form of a library.
- Only two buttons: `start` and `stop`. The first one accepts the configuration in TOML format.
- For tunnel listener to work, `wintun.dll` (architecture matching the `vpn_easy` binary)
  must be in the DLL search path.
- For tunnel listener to work, the process must have administrator privileges.

## Building from Source

Use the standard CMake workflow (requires Conan for dependency management):

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --target vpn_easy vpn_easy_service
```

## Building the Distribution Package

The `build_package.ps1` script builds the adapter and creates a ZIP archive suitable for
distribution via GitHub Maven Packages.

The script automatically downloads the wintun binaries from [wintun.net](https://www.wintun.net/)
based on the version in `third-party/wintun/VERSION`. To use an internal mirror (e.g. Artifactory),
pass the `-WintunUrl` parameter:

```powershell
# Uses wintun.net (default)
./scripts/build_package.ps1

# Uses Artifactory mirror (as in CI)
./scripts/build_package.ps1 -WintunUrl "https://artifactory.example.com/binaries/wintun-0.14.1.zip"
```

### Usage

```powershell
# Build for amd64 (default)
./scripts/build_package.ps1

# Build for arm64
./scripts/build_package.ps1 -Arch arm64

# Override version
./scripts/build_package.ps1 -Version 1.2.3

# Skip build step (re-package existing build artifacts)
./scripts/build_package.ps1 -SkipBuild
```

Output: `artifacts/trusttunnel-client-windows-<arch>-<version>.zip`

### Package Structure

The ZIP archive contains a complete CMake package:

```bash
trusttunnel-client-windows-amd64-1.1.3/
├── include/
│   └── vpn/
│       ├── vpn_easy.h            # VPN start/stop API
│       ├── vpn_easy_service.h    # Windows service control API
│       └── platform.h            # Platform definitions (WIN_EXPORT, etc.)
├── lib/
│   ├── vpn_easy.lib              # Import library (for link time)
│   └── cmake/
│       └── TrustTunnelClientWindows/
│           └── TrustTunnelClientWindowsConfig.cmake
├── bin/
│   ├── vpn_easy.dll              # Shared library (contains all transitive deps)
│   ├── vpn_easy_service.exe      # VPN Windows service binary
│   └── wintun.dll                # Wintun driver DLL
└── WINTUN_LICENSE.txt
```

The shared library (`vpn_easy.dll`) contains all transitive static dependencies
(libevent, OpenSSL, quiche, nghttp2, ldns, etc.) linked in at build time.
The consumer does **not** need to provide any third-party libraries — just
`vpn_easy.lib` at link time and `vpn_easy.dll` at runtime.

## Local Development / Testing

To test the package locally with the production Flutter app without publishing to Maven:

### Option A: Use the staging directory directly (fastest)

The build script creates a staging directory with the exact same layout as the ZIP.
Point the production app at it via `CMAKE_PREFIX_PATH` — no extraction needed.

```powershell
# In vpn-libs: build the package
cd platform/windows
./scripts/build_package.ps1 -Version 0.0.0-dev

# Note the staging path, e.g.:
#   C:\Dev\vpn-libs\platform\windows\staging\trusttunnel-client-windows-amd64-0.0.0-dev
```

Then in the production Flutter app's `windows/runner/CMakeLists.txt`:

```cmake
# For local dev: point to the vpn-libs staging directory
set(TRUSTTUNNEL_DIR "C:/Dev/vpn-libs/platform/windows/staging/trusttunnel-client-windows-amd64-0.0.0-dev")
list(APPEND CMAKE_PREFIX_PATH "${TRUSTTUNNEL_DIR}/lib/cmake")

find_package(TrustTunnelClientWindows REQUIRED)

target_link_libraries(${BINARY_NAME} PRIVATE TrustTunnelClientWindows::vpn_easy)
add_dependencies(${BINARY_NAME} TrustTunnelClientWindows::vpn_easy_service)
```

Or pass it on the command line without modifying CMakeLists.txt:

```powershell
# In the production app:
flutter build windows ^
    --dart-define=CMAKE_PREFIX_PATH=C:/Dev/vpn-libs/platform/windows/staging/trusttunnel-client-windows-amd64-0.0.0-dev/lib/cmake
```

### Option B: Extract the ZIP to a fixed path

This simulates the exact same flow the production app will use when downloading from Maven.

```powershell
# Build the ZIP
./scripts/build_package.ps1 -Version 0.0.0-dev

# Extract to a fixed location in the production app
Expand-Archive -Path artifacts/trusttunnel-client-windows-amd64-0.0.0-dev.zip `
    -DestinationPath "C:\Dev\production-app\third_party\trusttunnel" -Force
```

Then in the production app's CMakeLists.txt:

```cmake
# Points to the extracted package (same path whether local or from Maven)
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/third_party/trusttunnel/lib/cmake")

find_package(TrustTunnelClientWindows REQUIRED)

target_link_libraries(${BINARY_NAME} PRIVATE TrustTunnelClientWindows::vpn_easy)
add_dependencies(${BINARY_NAME} TrustTunnelClientWindows::vpn_easy_service)
```

For subsequent rebuilds, just re-run the build script and re-extract:

```powershell
# Rebuild + re-extract in one step
./scripts/build_package.ps1 -Version 0.0.0-dev
Expand-Archive -Path artifacts/trusttunnel-client-windows-amd64-0.0.0-dev.zip `
    -DestinationPath "C:\Dev\production-app\third_party\trusttunnel" -Force
```

### Option C: FetchContent with a local file:// URL

This uses the same `FetchContent` approach as the Maven flow, but pointed at a local ZIP:

```cmake
include(FetchContent)

FetchContent_Declare(
    TrustTunnelClientWindows
    URL "file:///C:/Dev/vpn-libs/platform/windows/artifacts/trusttunnel-client-windows-amd64-0.0.0-dev.zip"
)
FetchContent_MakeAvailable(TrustTunnelClientWindows)

target_link_libraries(${BINARY_NAME} PRIVATE TrustTunnelClientWindows::vpn_easy)
add_dependencies(${BINARY_NAME} TrustTunnelClientWindows::vpn_easy_service)
```

This is the closest to the production FetchContent flow — only the URL changes.

## Publishing to GitHub Maven Packages

```powershell
# Set credentials
$env:GITHUB_USERNAME = "your-username"
$env:GITHUB_TOKEN = "ghp_..."  # PAT with write:packages scope

# Publish
./scripts/publish_maven.ps1 -Version 1.1.3 -Arch amd64
./scripts/publish_maven.ps1 -Version 1.1.3 -Arch arm64
```

## Consuming the Package in a Flutter Application

### Architecture: Separate Packages Per Architecture

amd64 and arm64 are distributed as **separate** packages because:

- Smaller download size for the consumer
- No ambiguity about which binaries are being used
- Maven coordinates naturally distinguish architectures
- The consumer always knows the target architecture at build time

### Method 1: FetchContent (Recommended)

Add this to your Flutter app's `windows/runner/CMakeLists.txt`:

```cmake
include(FetchContent)

# Download the TrustTunnel Windows adapter from GitHub Maven Packages
set(TRUSTTUNNEL_VERSION "1.1.3")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
    set(TRUSTTUNNEL_ARCH "amd64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
    set(TRUSTTUNNEL_ARCH "arm64")
endif()

FetchContent_Declare(
    TrustTunnelClientWindows
    URL "https://maven.pkg.github.com/TrustTunnel/TrustTunnelClient/com/adguard/trusttunnel/trusttunnel-client-windows-${TRUSTTUNNEL_ARCH}/${TRUSTTUNNEL_VERSION}/trusttunnel-client-windows-${TRUSTTUNNEL_ARCH}-${TRUSTTUNNEL_VERSION}.zip"
    URL_HASH "SHA256=<expected-hash>"  # Recommended: verify the download
)
FetchContent_MakeAvailable(TrustTunnelClientWindows)

# Link against the VPN adapter library
target_link_libraries(${BINARY_NAME} PRIVATE TrustTunnelClientWindows::vpn_easy)

# Ensure the VPN service executable is built alongside the app
add_dependencies(${BINARY_NAME} TrustTunnelClientWindows::vpn_easy_service)
```

### Method 2: Manual Download + find_package

1. Download the ZIP from GitHub Maven Packages
2. Extract it to a known location (e.g., `third_party/trusttunnel/`)
3. In your `CMakeLists.txt`:

```cmake
# Point CMake to the extracted package
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/third_party/trusttunnel/lib/cmake")

find_package(TrustTunnelClientWindows REQUIRED)

target_link_libraries(${BINARY_NAME} PRIVATE TrustTunnelClientWindows::vpn_easy)
add_dependencies(${BINARY_NAME} TrustTunnelClientWindows::vpn_easy_service)
```

### Method 3: CMake Download at Configure Time

For a self-contained setup that doesn't require FetchContent:

```cmake
# Download and extract the TrustTunnel adapter package
set(TRUSTTUNNEL_VERSION "1.1.3")
set(TRUSTTUNNEL_ARCH "amd64")
set(TRUSTTUNNEL_DIR "${CMAKE_BINARY_DIR}/trusttunnel-client-windows")

if(NOT EXISTS "${TRUSTTUNNEL_DIR}/lib/cmake/TrustTunnelClientWindows")
    file(DOWNLOAD
        "https://maven.pkg.github.com/TrustTunnel/TrustTunnelClient/com/adguard/trusttunnel/trusttunnel-client-windows-${TRUSTTUNNEL_ARCH}/${TRUSTTUNNEL_VERSION}/trusttunnel-client-windows-${TRUSTTUNNEL_ARCH}-${TRUSTTUNNEL_VERSION}.zip"
        "${CMAKE_BINARY_DIR}/trusttunnel-client-windows.zip"
        STATUS DOWNLOAD_STATUS
    )
    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    if(NOT STATUS_CODE EQUAL 0)
        message(FATAL_ERROR "Failed to download TrustTunnel adapter")
    endif()
    file(ARCHIVE_EXTRACT
        INPUT "${CMAKE_BINARY_DIR}/trusttunnel-client-windows.zip"
        DESTINATION "${CMAKE_BINARY_DIR}"
    )
endif()

list(APPEND CMAKE_PREFIX_PATH "${TRUSTTUNNEL_DIR}/lib/cmake")
find_package(TrustTunnelClientWindows REQUIRED)

target_link_libraries(${BINARY_NAME} PRIVATE TrustTunnelClientWindows::vpn_easy)
add_dependencies(${BINARY_NAME} TrustTunnelClientWindows::vpn_easy_service)
```

### Deploying Binaries

The `vpn_easy.dll`, `vpn_easy_service.exe`, and `wintun.dll` must be present alongside the application
executable at runtime. Add these install rules to copy them:

```cmake
# Copy runtime binaries next to the app executable
install(FILES
    "${TrustTunnelClientWindows_DIR}/../../../bin/vpn_easy.dll"
    "${TrustTunnelClientWindows_DIR}/../../../bin/vpn_easy_service.exe"
    "${TrustTunnelClientWindows_DIR}/../../../bin/wintun.dll"
    DESTINATION bin
)
```

Or for development, use a post-build step:

```cmake
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TrustTunnelClientWindows_DIR}/../../../bin/vpn_easy.dll"
        $<TARGET_FILE_DIR:${BINARY_NAME}>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TrustTunnelClientWindows_DIR}/../../../bin/vpn_easy_service.exe"
        $<TARGET_FILE_DIR:${BINARY_NAME}>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${TrustTunnelClientWindows_DIR}/../../../bin/wintun.dll"
        $<TARGET_FILE_DIR:${BINARY_NAME}>
)
```
