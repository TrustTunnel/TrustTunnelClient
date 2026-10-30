#pragma once

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#if defined(__APPLE__) && !TARGET_OS_IPHONE

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ag {

/// Directory macOS requires a system extension host app to be installed in.
static constexpr std::string_view SYSEXT_HOST_APP_INSTALL_DIR = "/Applications";

/// Return the directory of the running executable, empty when it cannot be determined.
std::filesystem::path executable_dir();

/// The host app the controller drives.
struct SysextApp {
    /// Bundle distributed with the CLI and installed at `install_location`; may be absent.
    std::filesystem::path shipped_bundle;
    /// Location the controller installs the host app bundle at; macOS activates the
    /// system extension from the installed copy.
    std::filesystem::path install_location;
    /// Name of the executable inside the bundle's `Contents/MacOS`; can contain spaces
    /// and must never be passed through a shell.
    std::string binary_name;
};

/// Runs a process and relays its result. An injectable spawn mechanism;
/// `SpawnProcessRunner` is the production implementation.
class ProcessRunner {
public:
    virtual ~ProcessRunner() = default;

    /// Run the given executable with the given arguments, relaying its standard streams.
    /// `argv[0]` is the executable path. Returns the exit status of the process, or
    /// `std::nullopt` when it could not be spawned (the reason is logged).
    virtual std::optional<int> run(const std::vector<std::string> &argv) = 0;
};

/// Production process runner backed by `posix_spawn`.
class SpawnProcessRunner final : public ProcessRunner {
public:
    std::optional<int> run(const std::vector<std::string> &argv) override;
};

/**
 * Mechanics of driving a macOS app bundle: staging the shipped copy into the install
 * location, running the installed copy, and bundle removal.
 */
class SysextController {
public:
    /// Wire the controller with the app to drive and the process runner.
    SysextController(SysextApp app, std::unique_ptr<ProcessRunner> runner);

    /// Copy the shipped host app bundle into the install location, replacing any existing
    /// copy. Returns false on failure (the reason is logged).
    bool stage_host_app() const;

    /// Run the installed host app with the given arguments. Returns false when the app is
    /// not installed, cannot be spawned, or exits with a non-zero status (the reason is
    /// logged).
    bool run_app(std::vector<std::string> arguments) const;

    /// Remove the host app bundle from the install location. Returns `true` when the
    /// bundle is gone or was absent, `false` when the removal failed (the reason is
    /// logged).
    bool remove_install_location_bundle() const;

private:
    SysextApp m_app;
    std::unique_ptr<ProcessRunner> m_runner;
};

} // namespace ag

#endif // defined(__APPLE__) && !TARGET_OS_IPHONE
