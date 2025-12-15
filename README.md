<p align="center">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_dark.svg" width="300px" alt="TrustTunnel" />
<img src="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_light.svg" width="300px" alt="TrustTunnel" />
</picture>
</p>

# <p align="center">TrustTunnel Client</p>
<p align="center">Free, fast, open-source and secure client for the TrustTunnel VPN</p>

<p align="center"><a href="https://github.com/TrustTunnel/TrustTunnel">Endpoint</a>
  · <a href="https://github.com/TrustTunnel/TrustTunnelFlutterClient">Flutter-based app</a>
  · <a href="https://agrd.io/ios_trusttunnel">App store</a>
  · <a href="https://agrd.io/android_trusttunnel">Play store</a>
</p>

TrustTunnel Client Libraris are a collection of C++ libraries that provide client network traffic
tunneling through an TrustTunnel endpoint.
It supports Linux, macOS, and Windows platforms.

If you are looking for a TrustTunnel CLI Client, please refer to the [trusttunnel/README.md](./trusttunnel/README.md)

---

## Table of Contents

- [Features](#features)
- [Build Instructions](#build-instructions)
    - [Prerequisites](#prerequisites)
    - [Building](#building)
- [Quick Start the TrustTunnel VPN Client](#quick-start-the-trusttunnel-vpn-client)
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

## Build Instructions

### Prerequisites

- [Python 3](https://www.python.org/downloads/) 3.13 or higher
- [CMake](https://cmake.org/download/) 3.24 or higher
- [LLVM](https://releases.llvm.org/) 17 or higher
- [Conan](https://github.com/conan-io/conan/releases) 2.0.5 or higher
- [Rust](https://www.rust-lang.org/tools/install) 1.85 or higher
- [Go](https://go.dev/dl/) 1.18.3 or higher
- [Ninja](https://formulae.brew.sh/formula/ninja) 1.13 or higher
- Windows-specific
    - A recent version of Perl,
      either [Active State Perl](https://www.activestate.com/products/perl/)
      or [Strawberry Perl](https://strawberryperl.com/).
      But the latter one adds GCC to `PATH`, which can confuse some build tools when identifying
      the compiler (removing `C:\Strawberry\c\bin` from `PATH` should resolve any problems).
    - [NASM](https://www.nasm.us/)
    - [Visual Studio](https://visualstudio.microsoft.com/vs/older-downloads/) 2019

### Building

#### For python externally managed environments 

You might get an error where Python will report some missing modules such as 

```shell
ModuleNotFoundError: No module named 'yaml'
```

Please use following commands:
```
python3 -m venv env
source env/bin/activate
pip3 install -r ./scripts/requirements.txt
```

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

* Windows:

    ```shell
    mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
      -DCMAKE_C_FLAGS_DEBUG=/MT ^
      -DCMAKE_CXX_FLAGS_DEBUG=/MT ^
      -G "Visual Studio 16 2019" ^
      ..
    cmake --build . --target vpnlibs_core
    ```

* macOS:

    ```shell
    mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DCMAKE_CXX_FLAGS="-stdlib=libc++" \
      ..
    cmake --build . --target vpnlibs_core
    ```

* Others:

    ```shell
    mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DCMAKE_CXX_FLAGS="-stdlib=libc++" \
      ..
    cmake --build . --target vpnlibs_core
    ```

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

## Quick Start the TrustTunnel VPN Client

To quickly configure and launch the VPN client, follow these steps:

1. [Build](#building) the wizard and client libraries.

2. Generate the minimal working configuration file using the setup wizard tool:

   ```shell
   ./setup_wizard --mode non-interactive \
     --address "127.0.0.1:443" --address "[::]:443" \
     --hostname example.org \
     --creds premium:premium \
     --cert cert.pem \
     --settings trusttunnel_client.toml
   ```

   or using config generated by the endpoint:

   ```shell
   ./setup_wizard --mode non-interactive \
     --endpoint_config premium.toml
     --settings trusttunnel_client.toml
   ```

   This results in the following configuration:

    * The endpoint is expected to listen to the port number 443 on the local host.
    * `example.com` is used as the hostname during TLS handshakes.
    * `premium` and `premium` are used as the username and password correspondingly.
    * `cert.pem` certificate is used to verify endpoint's TLS certificate during the handshake.
      It can be obtained after the [endpoint](#companion-endpoint-repository) setup procedure.
    * Implicitly, the outbound traffic listener method is set to the TUN device.
    * The configuration file is named `trusttunnel_client.toml`.

3. Start the client:

   ```shell
   # sudo is required because TUN device is used by default
   sudo ./trusttunnel_client --config trusttunnel_client.toml
   ```

For detailed explanations, see the [client README](./trusttunnel/README.md).

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
    * If you have already exported the library in this way, the cached version must be purged: `conan remove -c vpn-libs/<commit_hash>`.

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
