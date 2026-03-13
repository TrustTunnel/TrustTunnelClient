# Development documentation

## Table of Contents

- [Prerequisites](#prerequisites)
- [Building](#building)
- [Debugging in Docker](#debugging-in-docker)
- [Debugging in VSCode/Windsurf](#debugging-in-vscode-windsurf)
- [Testing Changes as a Conan Dependency](#testing-changes-as-a-conan-dependency)
- [Companion Endpoint Repository](#companion-endpoint-repository)
- [Platform adapters](#platform-adapters)

## Prerequisites

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
        - Windows: Refer to the official [install page](https://visualstudio.microsoft.com/downloads/).

          Select `Desktop development with C++` workload and `Windows SDK` component in the installer.

## Building

### Prepare developer environment

Run `make init` to prepare the developer environment and set up git hooks.

### Using Makefile

This command builds and exports required binaries to the `bin` directory:

```shell
EXPORT_DIR=bin make build_and_export_bin
```

`EXPORT_DIR=bin` can be omitted. `bin` is the default value for `EXPORT_DIR`.
You can change the output directory path by specifying other value.

### Manual build

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
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo `
      -DCMAKE_C_COMPILER="cl.exe" `
      -DCMAKE_CXX_COMPILER="cl.exe" `
      -G "Ninja" `
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

## Debugging in Docker

For remote debugging with LLDB in a Docker container (useful for Linux debugging from macOS or
running with elevated privileges):

1. **Start the debug container:**

    ```shell
    docker-compose -f .devcontainer/docker-compose.yml up -d --build
    ```

2. **Build inside the container:**

    ```shell
    docker-compose -f .devcontainer/docker-compose.yml exec trusttunnel-debug \
        bash -c "cd /workspace && SKIP_VENV=1 BUILD_TYPE=debug make build_trusttunnel_client build_wizard"
    ```

3. **Generate configuration:**

    Run the setup wizard to generate a client configuration file:

    ```shell
    docker-compose -f .devcontainer/docker-compose.yml exec -w /workspace/build trusttunnel-debug \
        /workspace/build/trusttunnel/setup_wizard
    ```

4. **Debug via LLDB:**

    Connect to the remote lldb-server from your host machine:

    ```shell
    lldb
    (lldb) platform select remote-linux
    (lldb) platform connect connect://localhost:12345
    (lldb) target create /workspace/build/trusttunnel/trusttunnel_client
    (lldb) breakpoint set --file trusttunnel_client.cpp --line 94
    (lldb) process launch -- --config /workspace/build/trusttunnel_client.toml
    ```

    Common LLDB commands:
    - `c` or `continue` — continue execution
    - `n` or `next` — step over
    - `s` or `step` — step into
    - `bt` — show backtrace
    - `frame variable` — show local variables
    - `p <expr>` — print expression

5. **Stop the container when done:**

    ```shell
    docker-compose -f .devcontainer/docker-compose.yml stop
    ```

## Debugging in VSCode/Windsurf

For integrated debugging in VSCode or Windsurf, install the
[CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) extension
and create the following configuration files in the `.vscode` directory:

**.vscode/tasks.json:**

Note, that `SKIP_BOOTSTRAP` is used instead of `SKIP_VENV`, you need to bootstrap
the dependencies in the container once by running:

```shell
docker-compose -f .devcontainer/docker-compose.yml exec trusttunnel-debug \
    bash -c "cd /workspace && SKIP_VENV=1 BUILD_TYPE=debug make build_trusttunnel_client"
```

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Build trusttunnel_client",
      "type": "shell",
      "command": "cmake",
      "args": ["--build", "build", "--target", "trusttunnel_client"],
      "group": "build",
      "problemMatcher": []
    },
    {
      "label": "Build trusttunnel_client (Docker)",
      "type": "shell",
      "command": "docker-compose",
      "args": [
        "-f", ".devcontainer/docker-compose.yml",
        "exec", "-T", "trusttunnel-debug",
        "bash", "-c",
        "cd /workspace && SKIP_BOOTSTRAP=1 BUILD_TYPE=debug make build_trusttunnel_client"
      ],
      "group": "build",
      "problemMatcher": []
    }
  ]
}
```

**.vscode/launch.json:**

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug trusttunnel_client",
      "type": "lldb",
      "request": "launch",
      "program": "${workspaceFolder}/build/trusttunnel/trusttunnel_client",
      "args": ["--config", "${workspaceFolder}/build/trusttunnel_client.toml"],
      "cwd": "${workspaceFolder}",
      "preLaunchTask": "Build trusttunnel_client"
    },
    {
      "name": "Debug trusttunnel_client (Docker)",
      "type": "lldb",
      "request": "launch",
      "initCommands": [
        "platform select remote-linux",
        "platform connect connect://localhost:12345"
      ],
      "targetCreateCommands": [
        "target create /workspace/build/trusttunnel/trusttunnel_client"
      ],
      "processCreateCommands": [
        "process launch -- --config /workspace/build/trusttunnel_client.toml"
      ],
      "sourceMap": {
        "/workspace": "${workspaceFolder}"
      },
      "preLaunchTask": "Build trusttunnel_client (Docker)"
    }
  ]
}
```

To debug:

1. Open the Run and Debug panel (Cmd+Shift+D / Ctrl+Shift+D)
2. Select the desired configuration from the dropdown
3. Press F5 to start debugging

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

## See also

- [README](README.md)
- [TrustTunnel CLI Client reference](trusttunnel/README.md)
- [Platform adapters](platform/README.md)
- [Android adapter](platform/android/README.md)
- [Apple adapter](platform/apple/README.md)
- [Windows adapter](platform/windows/README.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE)
