#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#if defined(__APPLE__) && !TARGET_OS_IPHONE

#include "vpn/trusttunnel/sysext.h"

#include <filesystem>
#include <utility>

#include <crt_externs.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/logger.h"
#include "vpn/platform.h"

using namespace ag; // NOLINT(google-build-using-namespace)

static const Logger g_logger("SYSEXT"); // NOLINT(readability-identifier-naming)

/// Check that the given path is an existing directory.
static bool is_existing_directory(const std::filesystem::path &path) {
    std::error_code ec;
    return std::filesystem::is_directory(path, ec) && !ec;
}

std::filesystem::path ag::executable_dir() {
    uint32_t size = 0;
    if (_NSGetExecutablePath(nullptr, &size) == 0) {
        return {};
    }
    std::vector<char> buffer(size);
    if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
        return {};
    }
    std::error_code ec;
    const std::filesystem::path canonical = std::filesystem::weakly_canonical(buffer.data(), ec);
    if (ec) {
        return {};
    }
    return canonical.parent_path();
}

SysextController::SysextController(SysextApp app, std::unique_ptr<ProcessRunner> runner)
        : m_app(std::move(app))
        , m_runner(std::move(runner)) {
}

std::optional<int> SpawnProcessRunner::run(const std::vector<std::string> &arguments) {
    // posix_spawn takes mutable string pointers; hand it copies of the arguments.
    std::vector<std::string> mutable_arguments = arguments;
    std::vector<char *> argv;
    argv.reserve(mutable_arguments.size() + 1);
    for (std::string &argument : mutable_arguments) {
        argv.push_back(argument.data());
    }
    argv.push_back(nullptr);

    pid_t pid = -1;
    if (posix_spawn(&pid, argv.front(), nullptr, nullptr, argv.data(), *_NSGetEnviron()) != 0) {
        const int code = sys::last_error();
        errlog(g_logger, "Failed to spawn '{}': {} ({})", argv.front(), sys::strerror(code), code);
        return std::nullopt;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        const int code = sys::last_error();
        errlog(g_logger, "Failed to wait for '{}': {} ({})", argv.front(), sys::strerror(code), code);
        return std::nullopt;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        errlog(g_logger, "'{}' was killed by signal {}", argv.front(), WTERMSIG(status));
    }
    return std::nullopt;
}

bool SysextController::stage_host_app() const {
    if (!is_existing_directory(m_app.shipped_bundle)) {
        errlog(g_logger, "The shipped host app bundle is missing: {}", m_app.shipped_bundle.string());
        return false;
    }
    // The shipped bundle is already at the install location when the CLI is placed in
    // /Applications; there is nothing to copy in that case.
    if (m_app.shipped_bundle == m_app.install_location) {
        return true;
    }

    std::error_code ec;
    std::filesystem::remove_all(m_app.install_location, ec);
    if (ec) {
        errlog(g_logger, "Failed to remove the installed app bundle {}: {}", m_app.install_location.string(),
                ec.message());
        return false;
    }

    std::filesystem::copy(m_app.shipped_bundle, m_app.install_location,
            std::filesystem::copy_options::recursive | std::filesystem::copy_options::copy_symlinks, ec);
    if (ec) {
        errlog(g_logger, "Failed to copy the app bundle into {}: {} (try running with sudo)",
                m_app.install_location.string(), ec.message());
        return false;
    }
    return true;
}

bool SysextController::run_app(std::vector<std::string> arguments) const {
    if (!is_existing_directory(m_app.install_location)) {
        errlog(g_logger, "The host app is not installed at {}", m_app.install_location.string());
        return false;
    }
    arguments.emplace(arguments.begin(), (m_app.install_location / "Contents" / "MacOS" / m_app.binary_name).string());
    dbglog(g_logger, "Spawning '{}'", arguments.front());
    const std::optional<int> exit_status = m_runner->run(arguments);
    if (!exit_status) {
        errlog(g_logger, "Failed to spawn the host app '{}'", arguments.front());
        return false;
    }
    if (*exit_status != 0) {
        errlog(g_logger, "The host app failed with exit status {}", *exit_status);
        return false;
    }
    return true;
}

bool SysextController::remove_install_location_bundle() const {
    std::error_code ec;
    std::string install_location = m_app.install_location.string();
    if (std::filesystem::exists(install_location, ec) && !ec) {
        std::filesystem::remove_all(install_location, ec);
        if (ec) {
            errlog(g_logger, "Failed to remove the host app bundle {}: {} (try running with sudo)", install_location,
                    ec.message());
            return false;
        }
    }
    return true;
}

#endif // defined(__APPLE__) && !TARGET_OS_IPHONE
