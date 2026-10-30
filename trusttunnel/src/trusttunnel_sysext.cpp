#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#if defined(__APPLE__) && !TARGET_OS_IPHONE

#include "vpn/trusttunnel/trusttunnel_sysext.h"

#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/logger.h"

using namespace ag; // NOLINT(google-build-using-namespace)

static const Logger g_logger("TRUSTTUNNEL_CLIENT_SYSEXT"); // NOLINT(readability-identifier-naming)

/// Host app command that activates the system extension after the bundle has been staged.
static constexpr std::string_view HOST_APP_INSTALL_COMMAND = "install";
/// Host app command that deactivates the system extension before the bundle is removed.
static constexpr std::string_view HOST_APP_UNINSTALL_COMMAND = "uninstall";

std::filesystem::path ag::default_shipped_bundle_location() {
    return executable_dir() / TRUSTTUNNEL_SYSEXT_BUNDLE_NAME;
}

std::filesystem::path ag::default_install_location() {
    return std::filesystem::path(SYSEXT_HOST_APP_INSTALL_DIR) / TRUSTTUNNEL_SYSEXT_BUNDLE_NAME;
}

TrustTunnelSysextController::TrustTunnelSysextController(std::filesystem::path shipped_bundle,
        std::filesystem::path install_location, std::unique_ptr<ProcessRunner> runner)
        : m_controller(SysextApp{std::move(shipped_bundle), std::move(install_location),
                               std::string(TRUSTTUNNEL_SYSEXT_BINARY_NAME)},
                  std::move(runner)) {
}

bool TrustTunnelSysextController::run(std::string_view command, const std::string &config_path) {
    if (command.empty()) {
        errlog(g_logger, "A --sysext subcommand is required");
        return false;
    }

    if (command == HOST_APP_INSTALL_COMMAND) {
        if (!m_controller.stage_host_app()) {
            errlog(g_logger, "Failed to stage the host app bundle, cannot install the system extension");
            return false;
        }
        return m_controller.run_app({std::string(command)});
    }

    if (command == HOST_APP_UNINSTALL_COMMAND) {
        if (!m_controller.run_app({std::string(command)})) {
            return false;
        }
        return m_controller.remove_install_location_bundle();
    }

    std::vector<std::string> arguments{std::string(command)};
    if (!config_path.empty()) {
        arguments.emplace_back("--config");
        arguments.push_back(config_path);
    }
    return m_controller.run_app(std::move(arguments));
}

#endif // defined(__APPLE__) && !TARGET_OS_IPHONE
