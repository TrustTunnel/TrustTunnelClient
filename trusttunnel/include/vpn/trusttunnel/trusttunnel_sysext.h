#pragma once

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#if defined(__APPLE__) && !TARGET_OS_IPHONE

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "vpn/trusttunnel/sysext.h"

namespace ag {

/// Must stay in sync with the app bundle built in `platform/macos-sysext-app`.
static constexpr std::string_view TRUSTTUNNEL_SYSEXT_BUNDLE_NAME = "TrustTunnel CLI System Extension Manager.app";
/// Must stay in sync with the app bundle built in `platform/macos-sysext-app`.
static constexpr std::string_view TRUSTTUNNEL_SYSEXT_BINARY_NAME = "TrustTunnel CLI System Extension Manager";

/// Default location of the host app bundle shipped with the CLI, next to the running binary.
std::filesystem::path default_shipped_bundle_location();

/// Default location the controller installs the host app bundle at, under the directory
/// macOS requires for system extension host apps.
std::filesystem::path default_install_location();

/**
 * Orchestrates the general sysext controller with the TrustTunnel protocol: staging the
 * host app bundle before `install`, removing it after `uninstall`, and forwarding every
 * other subcommand to the installed host app.
 */
class TrustTunnelSysextController {
public:
    /// Wire the controller with the host app bundle locations and the process runner;
    /// the defaults match the production layout.
    TrustTunnelSysextController(std::filesystem::path shipped_bundle = default_shipped_bundle_location(),
            std::filesystem::path install_location = default_install_location(),
            std::unique_ptr<ProcessRunner> runner = std::make_unique<SpawnProcessRunner>());

    /// Run the given subcommand. `install` stages the bundle before running the host app,
    /// `uninstall` removes it after a successful run, and every other subcommand is
    /// forwarded to the installed host app as is. The config path is forwarded to the host
    /// app when it is non-empty. Returns true on success, false otherwise (the reason is
    /// logged).
    bool run(std::string_view command, const std::string &config_path);

private:
    SysextController m_controller;
};

} // namespace ag

#endif // defined(__APPLE__) && !TARGET_OS_IPHONE
