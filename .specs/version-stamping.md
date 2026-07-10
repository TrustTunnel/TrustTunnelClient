# Spec: version stamping without `set_version.sh`

Status: **IMPLEMENTED**
Related: `cmake/version.cmake`, `trusttunnel/setup_wizard/build.rs`,
`platform/android/lib/build.gradle.kts`, `platform/apple/build_framework.sh`,
`platform/apple/TrustTunnelClient.podspec`

## Problem

`scripts/set_version.sh` patched version fields **in place** across tracked
source files (`version.h`, `version.rs`, the Windows `.rc` files, the Android
Gradle script, the Apple podspec / Xcode project / framework CMake). Running it
during a build left the working tree dirty (`git status` contamination) and made
`git describe --dirty` flip the stamped build to "dirty". We want versioned
builds from a clean tree.

## Version source order (every toolchain implements the same order)

1. `-DTT_CLIENT_VERSION=<value>` CMake cache/var (also `-PttClientVersion` for
   Gradle) — the explicit override;
2. the `TT_CLIENT_VERSION` **environment variable** — the single CI override,
   set once per job;
3. `git describe --tags --match 'v*'` (leading `v` stripped) — a plain local
   build is self-versioning;
4. `0.0.0-git` fallback (never hard-fails the build).

`TT_CLIENT_VERSION` replaces `set_version.sh` everywhere; the script is removed.

## Per-surface mechanism

| Surface | File | How the version arrives |
|---|---|---|
| C++ `--version` | `trusttunnel/include/vpn/trusttunnel/version.h.in` → generated `version.h` | `cmake/version.cmake` + `configure_file` into `${build}/gen` (git-ignored), that dir added `BEFORE` the source include |
| Windows `trusttunnel_client` | `trusttunnel/trusttunnel_client.rc.in` → generated `.rc` | `configure_file` in `trusttunnel/CMakeLists.txt` (`@TT_CLIENT_VERSION_COMMAS@` / `_FULL@`) |
| Rust `setup_wizard` `--version` | `trusttunnel/setup_wizard/src/version.rs` (`env!`) | `build.rs` resolves the version and emits `cargo:rustc-env=TT_CLIENT_VERSION` |
| Windows `setup_wizard` | `trusttunnel/setup_wizard/resources/setup_wizard.rc.in` → OUT_DIR `.rc` | `build.rs` renders the template and `windres`-compiles it |
| Android Maven AAR | `platform/android/lib/build.gradle.kts` | `resolveTtClientVersion(project)` sets `version` and forwards `-DTT_CLIENT_VERSION` to the native build |
| Apple framework (CMake path) | `platform/apple/VpnClient/CMakeLists.txt` | `VERSION ${TT_CLIENT_VERSION_CORE}` (numeric core) |
| Apple xcframework (xcodebuild path) | `platform/apple/build_framework.sh` | resolves the version, exports `TT_CLIENT_VERSION`, passes `MARKETING_VERSION`/`CURRENT_PROJECT_VERSION`/`DYLIB_CURRENT_VERSION` build-setting overrides |
| Apple podspec | `platform/apple/TrustTunnelClient.podspec` | `resolve_tt_client_version` (env → git describe → fallback) |

`cmake/version.cmake` exports three cache vars: `TT_CLIENT_VERSION_FULL` (free
form, e.g. `1.2.3-beta.4`), `TT_CLIENT_VERSION_CORE` (numeric `X.Y.Z`, for the
Mach-O framework version) and `TT_CLIENT_VERSION_COMMAS` (`X,Y,Z` for Windows
`FILEVERSION`).

## CI

The build/deploy jobs (`build-console.yml`, `deploy-android.yml`,
`deploy-apple.yml`) rely on **git describe** (source 3), not the changelog. They
check out with `fetch-depth: 0` so tags are available. In the publish flow the
`tag` job creates `vX.Y.Z` on the merge commit *before* the builds run, so
`git describe` on that commit returns the exact release version.

The `TT_CLIENT_VERSION` **override** (source 2) is only wired where git describe
cannot see the intended version: a manual `version` input on the deploy
workflows, and — in future — a build of the release-bump PR opened by Create
Release PR, whose `CHANGELOG.md` already names the version being released but
whose tag does not exist yet (so a test needing the "future" version would
otherwise git-describe the previous release). No current test consumes the
version, so nothing sets it from the changelog today.

## Generated (git-ignored) artifacts

`trusttunnel/include/vpn/trusttunnel/version.h`, `trusttunnel/trusttunnel_client.rc`,
`trusttunnel/setup_wizard/resources/setup_wizard.rc` — rendered from the
committed `*.in` templates; never committed.

## Out of scope

- `scripts/install.sh` `version='…'` — a distributed installer default that runs
  on the end user's machine (no repo / git available); it is not a build-time
  stamp and keeps its own value.
- `platform/apple/TrustTunnelClient.xcodeproj/project.pbxproj` marketing/current
  version fields stay as a static local-dev default; the CI xcframework build
  overrides them via `build_framework.sh`.
