# AGENTS.md — Project Guide for AI Coding Agents

## Project Overview

This is reposoitory TrustTunnelClient, which contains libraries and command-line client for TrustTunnel protocol. The protocol is compatible with HTTP/1.1, HTTP/2, and QUIC, and supports tunneling TCP, UDP, and ICMP traffic. The libraries run on Linux, macOS, and Windows.

See [README.md](README.md) for full product details and
[DEVELOPMENT.md](DEVELOPMENT.md) for prerequisite setup.

## Tech Stack

- **C++20** (primary), **C11** — core libraries
- **Rust 1.85** — `trusttunnel/setup_wizard/`, `trusttunnel/settings/`,
  `trusttunnel/deeplink-ffi/`
- **Kotlin** — Android platform adapter
- **Swift / Objective-C** — Apple platform adapter
- **Dart (Flutter)** — test app (`platform/testapp/`)
- **CMake 3.24+** — build system
- **Conan 2.0.5+** — C++ package manager
- **Ninja** — build backend
- **Clang / LLVM 17+** (LLVM 19 on macOS) — compiler and tooling

## Directory Structure

| Directory | Purpose |
| --- | --- |
| `common/` | Shared utilities used across all modules: FSM, event loop, platform abstractions, settings |
| `core/` | Core VPN logic: tunnel, upstream connectors (HTTP/2, HTTP/3), DNS, SOCKS listener, TUN device |
| `net/` | Network layer: HTTP sessions, TLS, QUIC, sockets, OS tunnel, DNS management, pinger |
| `tcpip/` | TCP/IP stack: lwIP integration, TCP/UDP/ICMP raw handling, packet pool |
| `trusttunnel/` | CLI client app, config parsing; contains Rust sub-crates: `deeplink-ffi/`, `settings/`, `setup_wizard/` |
| `platform/android/` | Android adapter (Kotlin/Gradle) |
| `platform/apple/` | Apple adapter (Swift/ObjC, CocoaPods, XCFramework) |
| `platform/windows/` | Windows adapter (C++/CMake) |
| `platform/testapp/` | Flutter test application for platform adapters |
| `third-party/` | Vendored dependencies: lwip, pcap_savefile, wintun |
| `scripts/` | Build helpers, Conan export, version increment, git hooks |
| `cmake/` | CMake modules: unit test helper, Conan bootstrapping/provider |
| `bamboo-specs/` | CI/CD pipeline definitions (Bamboo) |
| `integration-tests/` | Docker-based integration test harness |

### Module Dependency Flow

```text
common ← core ← trusttunnel (CLI client)
common ← net  ← core
common ← tcpip ← core
```

`platform/*` adapters wrap `core` for their respective OS.

## Build Commands

Run `make init` once after cloning to set up git hooks.

| Command | What It Does |
| --- | --- |
| `make init` | Configure git hooks path to `./scripts/hooks` |
| `make build_libs` | Bootstrap Conan deps → CMake configure → build `vpnlibs_core` |
| `make build_trusttunnel_client` | Build the CLI client binary (depends on `build_libs`) |
| `make build_wizard` | Build the setup wizard binary |
| `make all` | Build all binaries (client + wizard) |
| `make test` | Run all tests (`test-cpp` + `test-rust`) |
| `make test-cpp` | Build libs → build test targets → run `ctest` |
| `make test-rust` | `cargo test` on the setup_wizard workspace |
| `make lint` | Run all linters (`lint-md` + `lint-rust` + `lint-cpp`) |
| `make lint-cpp` | `clang-format` check + `clangd-tidy` |
| `make lint-rust` | `cargo clippy` + `cargo fmt --check` |
| `make lint-md` | `markdownlint .` |
| `make lint-fix` | Auto-fix all fixable linter issues |
| `make compile_commands` | Generate `compile_commands.json` for IDE integration |
| `make clean` | Clean build artifacts |

Set `BUILD_TYPE=debug` for debug builds (default is `release` →
`RelWithDebInfo`).

## Code Style

### C++

- LLVM-based style, 4-space indent, 120-column limit (see `.clang-format`)
- Pointers and references: `*` and `&` bind to the identifier (right side),
  e.g. `int *ptr`, `const std::string &ref` (LLVM convention)
- Line continuations (wrapped arguments, conditions) indent 8 spaces
- No short functions/blocks on a single line
- Constructor initializers break before comma
- Binary operators break before the operator (non-assignment)
- Extensive static analysis via `.clang-tidy`, all warnings are errors
- Naming conventions (from `.clang-tidy`):
    - `lower_case`: variables, functions, methods, namespaces
    - `CamelCase`: classes, structs, enums, typedefs, template type parameters
    - `UPPER_CASE`: constants, `constexpr` locals, static constants
    - Private/protected members prefixed with `m_`, globals with `g_`
- Use `libc++` (not `libstdc++`)
- Use static storage duration instead of anonymous namespaces for internal linkage where possible 
    - (e.g. `static const int VALUE = 42;` instead of putting it in an anonymous namespace)
- Function descriptions are written in imperative language
    - e.g. "Calculate the sum of two numbers" instead of "Calculates the sum of two numbers"

### Rust

- Standard `rustfmt` formatting, enforced by `cargo fmt`
- `clippy` with `-D warnings` (all warnings are errors)

### Markdown

- Linted with `markdownlint` (config in `.markdownlint.json`)
- Unordered lists use dashes (`-`), indented 4 spaces
- No line-length limit
- **Markdown table formatting (MD060)**: When the Markdownlint MD060 rule
  triggers, switch to tight table formatting with spaces. Example:

  ```markdown
  | Column1 | Column2 |
  | --- | --- |
  | Value 1 | Value 2 |
  ```

  Do NOT use extra padding or alignment characters beyond single spaces.

### General

- Prefer existing patterns over inventing new ones
- Keep changes minimal and focused
- Tests live in `test/` subdirectories alongside the module they cover
- Logging guidelines:
    - Use `DEBUG` level for verbose debug info, `INFO` for high-level events,
      `WARN` for recoverable issues, and `ERROR` for critical (unrecoverable) errors
    - Very frequent events (e.g. every packet) should be logged at `DEBUG` level, while important state changes (e.g. connection established, error occurred) should be at `INFO` or higher
    - Include relevant context in log messages (e.g. connection ID, error code)
    - Avoid logging sensitive information (e.g. IP addresses, payload data)

## Docker Debug Environment

The `.devcontainer/` directory provides a Docker-based remote debugging setup
(copy `devcontainer.json.example` to `devcontainer.json` to enable it).

- **Image**: Ubuntu 24.04 with clang, cmake, ninja, rust, conan, lldb
- **Purpose**: Remote LLDB debugging, especially for Linux debugging from macOS
- **Start**: `docker-compose -f .devcontainer/docker-compose.yml up -d --build`
- **Build inside**: `docker-compose -f .devcontainer/docker-compose.yml exec trusttunnel-debug bash -c "cd /workspace && SKIP_VENV=1 BUILD_TYPE=debug make build_trusttunnel_client build_wizard"`
- **Debug**: Connect to `lldb-server` on port 12345

See [DEVELOPMENT.md](DEVELOPMENT.md#debugging-in-docker) for full instructions.

## Dependencies

Managed via Conan. Key libraries:

- **dns-libs**, **native_libs_common** — AdGuard shared libraries
- **libevent** — async event loop
- **nghttp2** — HTTP/2
- **quiche** — HTTP/3 / QUIC (disabled on MIPS)
- **openssl** (BoringSSL) — TLS
- **nlohmann_json**, **tomlplusplus** — config parsing
- **cxxopts** — CLI argument parsing
- **magic_enum** — enum reflection

Local conan cache is populated by `make bootstrap_deps` which is dependency for many other make commands.

To find headers for **dns-libs** and **native_libs_common** (e.g. when
resolving symbols or includes), run `make list-deps-dirs` to list Conan package
directories, then look in each directory's `include/` subdirectory.

## Mandatory Task Rules

You MUST follow the following rules for EVERY task that you perform:

- You MUST verify it with linter, formatter, and TypeScript compiler.

  Use the following commands:
    - `make` to check if code builds
    - `make test` to build and run unit tests
    - `make lint` to run the linters
    - `make lint-fix` to fix linting issues that can be fixed automatically
    - `make clang-format` to check the formatting

- You MUST update the unit tests for changed code.

- You MUST run tests with the `make test` script to verify that your changes do
  not break existing functionality.

- When making changes to the project structure, ensure the Project structure
  section in `AGENTS.md` is updated and remains valid.

- If the prompt essentially asks you to refactor or improve existing code, check
  if you can phrase it as a code guideline. If it's possible, add it to
  the relevant Code Guidelines section in `AGENTS.md`.

- After completing the task you MUST verify that the code you've written
  follows the Code Guidelines in this file.
