<!-- markdownlint-disable MD041 -->
<p align="center">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_dark.svg" width="300px" alt="TrustTunnel" />
<img src="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_light.svg" width="300px" alt="TrustTunnel" />
</picture>
</p>

<p align="center">Free, fast, open-source and secure client for the TrustTunnel VPN</p>

<p align="center"><a href="https://github.com/TrustTunnel/TrustTunnel">Endpoint</a>
  · <a href="https://github.com/TrustTunnel/TrustTunnelFlutterClient">Flutter-based app</a>
  · <a href="https://agrd.io/ios_trusttunnel">App store</a>
  · <a href="https://agrd.io/android_trusttunnel">Play store</a>
</p>

TrustTunnel Client Libraries are a collection of C++ libraries that provide client network traffic
tunneling through a TrustTunnel endpoint.
It supports Linux, macOS, and Windows platforms.

If you are looking for a TrustTunnel CLI Client, please refer to the [Quick Start](#quick-start-the-trusttunnel-cli-client)

---

## Table of Contents

- [Features](#features)
- [Quick Start the TrustTunnel CLI Client](#quick-start-the-trusttunnel-cli-client)
- [Build Instructions](#build-instructions)
    - [Prerequisites](#prerequisites)
    - [Building](#building)
- [Testing Changes as a Conan Dependency](#testing-changes-as-a-conan-dependency)
- [Companion Endpoint Repository](#companion-endpoint-repository)
- [Platform adapters](#platform-adapters)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

- **TrustTunnel VPN Protocol**: The library implements the TrustTunnel VPN protocol, which is compatible
  with HTTP/1.1, HTTP/2, and QUIC.
  By mimicking regular network traffic, it becomes more difficult for government regulators to
  detect and block.

- **Traffic Tunneling**: The library is capable of tunneling TCP, UDP, and ICMP traffic from the
  client to the endpoint and back.

- **Cross-Platform Support**: It supports Linux, macOS, and Windows platforms, providing a
  consistent experience across different operating systems.

- **System-Wide Tunnel and SOCKS5 Proxy**: It can be set up as a system-wide tunnel, utilizing a
  virtual network interface, as well as a SOCKS5 proxy.

- **Split Tunneling**: The library supports split tunneling, allowing users to exclude connections
  to certain domains or hosts from routing through the VPN endpoint, or vice versa, only routing
  connections to specific domains or hosts through the endpoint based on an exclusion list.

- **Custom DNS Upstream**: Users can specify a custom DNS upstream, which is used for DNS queries
  routed through the VPN endpoint.

---

## Quick Start the TrustTunnel CLI Client

If you haven't yet set up the endpoint, refer to the [Endpoint setup](https://github.com/TrustTunnel/TrustTunnel/blob/master/README.md#endpoint-setup) documentation.

Once you have obtained the exported endpoint configuration for the client, refer to the [Client setup](https://github.com/TrustTunnel/TrustTunnel/blob/master/README.md#client-setup) documentation.

---

## Build Instructions

### Prerequisites

- Python 3.13 or higher
    - macOS: `brew install python`
    - Linux (Debian/Ubuntu): `apt install python3`
    - Windows (Chocolatey): `choco install python`
- CMake 3.24 or higher
    - macOS: `brew install cmake`
    - Linux (Debian/Ubuntu): `apt install cmake`
    - Windows (Chocolatey): `choco install cmake`
- LLVM 17 or higher
    - macOS: `brew install llvm@19`

        On macOS LLVM 19 is required for compatibility with the Apple's
        compiler.

        Also, add `clang-format` and `clang-tidy` to PATH:

        ```shell
        ln -s /opt/homebrew/opt/llvm@19/bin/clang-format /opt/homebrew/bin/clang-format
        ln -s /opt/homebrew/opt/llvm@19/bin/clang-tidy /opt/homebrew/bin/clang-tidy
        ln -s /opt/homebrew/opt/llvm@19/bin/run-clang-tidy /opt/homebrew/bin/run-clang-tidy
        ```

    - Linux (Debian/Ubuntu): `apt install llvm clang libc++-dev`
    - Windows (Chocolatey): `choco install llvm`
- Conan 2.0.5 or higher
    - macOS: `brew install conan`
    - Linux (Debian/Ubuntu): Refer to the [official documentation](https://conan.io/downloads)
    - Windows (Chocolatey): `choco install conan`
- Rust 1.85 or higher
    - macOS/Linux: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain 1.85 -y`
    - Windows: Refer to the official [documentation](https://rust-lang.org/tools/install/)
- Go 1.18.3 or higher
    - macOS: `brew install go`
    - Linux (Debian/Ubuntu): `apt install golang`
    - Windows (Chocolatey): `choco install golang`
- Ninja 1.13 or higher
    - macOS: `brew install ninja`
    - Linux (Debian/Ubuntu): `apt install ninja-build`
    - Windows (Chocolatey): `choco install ninja`
- Windows-specific
    - Perl
        - Windows (Chocolatey): `choco install strawberryperl`
      > Note: Strawberry Perl adds `GCC` to your `PATH`, which can conflict with other build tools. If you encounter compiler identification issues, remove `C:\Strawberry\c\bin` from your system `PATH`.
    - NASM
        - Windows (Chocolatey): `choco install nasm`
    - Visual Studio 2022
        - Windows (Chocolatey): `choco install visualstudio2022buildtools`

### Building

#### Prepare developer environment

Run `make init` to prepare the developer environment and set up git hooks.

#### Using Makefile

This command builds and exports required binaries to the `bin` directory:

```shell
EXPORT_DIR=bin make build_and_export_bin
```

`EXPORT_DIR=bin` can be omitted. `bin` is the default value for `EXPORT_DIR`.
You can change the output directory path by specifying other value.

#### Manually

If it's a clean build, export custom Conan packages to the local Conan repository.
Refer to the [details here](https://github.com/AdguardTeam/NativeLibsCommon/blob/master/README.md),
or run the helper script:

```shell
./scripts/bootstrap_conan_deps.py
```

To build the main library:

- Windows:

    ```shell
    mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
      -DCMAKE_C_FLAGS_DEBUG=/MT ^
      -DCMAKE_CXX_FLAGS_DEBUG=/MT ^
      -G "Visual Studio 17 2022" ^
      ..
    cmake --build . --target vpnlibs_core
    ```

- macOS:

    ```shell
    mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DCMAKE_CXX_FLAGS="-stdlib=libc++" \
      ..
    cmake --build . --target vpnlibs_core
    ```

- Others:

    ```shell
    mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DCMAKE_CXX_FLAGS="-stdlib=libc++" \
      ..
    cmake --build . --target vpnlibs_core
    ```

> Alternatively, you could replace `-DCMAKE_BUILD_TYPE=RelWithDebInfo` with `-DCMAKE_BUILD_TYPE=Debug` to build the debug executables.

To run tests:

```shell
cmake --build . --target tests && ctest
```

To build the trusttunnel client application, run:

```shell
cmake --build . --target trusttunnel_client
```

To build the setup wizard tool, run:

```shell
cmake --build . --target setup_wizard
```

For more information, refer to the [client's README](./trusttunnel/README.md) file.

---

## Testing Changes as a Conan Dependency

To test local changes in the library when used as a Conan package dependency, follow these steps:

1) If the default `vcs_url` in `<root>/conanfile.py` is not suitable, change it accordingly.
2) Commit the changes you wish to test.
3) Execute `./script/conan_export.py local`. This script will export the package, assigning the last commit hash as its version.
4) In the project that depends on `vpn-libs`, update the version to `<commit_hash>` (where `<commit_hash>` is the hash of the target commit):
   Replace `vpn-libs/1.0.0@adguard/oss` with `vpn-libs/<commit_hash>@adguard/oss`.
5) Re-run the cmake command.
   Note:
    - If you have already exported the library in this way, the cached version must be purged: `conan remove -c vpn-libs/<commit_hash>`.

## Companion Endpoint Repository

Complementary endpoint implementation for the TrustTunnel VPN can be found in
the [TrustTunnel Endpoint repository](https://github.com/TrustTunnel/TrustTunnel).

## Platform adapters

This repository also contains the adapters to the TrustTunnel libraries for Android, Apple and Windows.
Check [platform/README.md](platform/README.md) for details

---

## Roadmap

While the library currently does not support peer-to-peer communication between clients, we have
plans to add this feature in future releases. Stay tuned for updates.

---

## License

Apache 2.0
