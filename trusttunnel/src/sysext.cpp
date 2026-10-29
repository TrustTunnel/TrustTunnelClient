#include "vpn/trusttunnel/sysext.h"

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <utility>

#include <cxxopts.hpp>
#include <toml++/toml.h>

#include "common/logger.h"
#include "utils.h"
#include "vpn/platform.h"

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <crt_externs.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <unistd.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

using namespace ag; // NOLINT(google-build-using-namespace)

namespace ag::sysext {

static constexpr std::string_view CONFIG_FILE_NAME = "config.toml";
static constexpr std::string_view APP_GROUP_LOGS_DIR = "logs";
/// Last lines of each log file printed by `print_log_tails` when a command fails.
static constexpr std::size_t LOG_TAIL_LINES = 20;

static const Logger g_logger("TRUSTTUNNEL_CLIENT_SYSEXT"); // NOLINT(readability-identifier-naming)

static const std::unordered_map<std::string_view, Command> COMMAND_MAP = {
        {"install", Command::install},
        {"start", Command::start},
        {"stop", Command::stop},
        {"status", Command::status},
        {"uninstall", Command::uninstall},
};

/// Check that the given path is an existing directory.
static bool is_existing_directory(std::string_view path) {
    std::error_code ec;
    return std::filesystem::is_directory(std::filesystem::path(path), ec) && !ec;
}

std::optional<Command> parse_command(std::string_view name) {
    if (auto it = COMMAND_MAP.find(name); it != COMMAND_MAP.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::string_view command_name(Command command) {
    switch (command) {
    case Command::install:
        return "install";
    case Command::start:
        return "start";
    case Command::stop:
        return "stop";
    case Command::status:
        return "status";
    case Command::uninstall:
        return "uninstall";
    }
    return {};
}

std::string container_config_path(std::string_view home_dir) {
    return (std::filesystem::path(home_dir) / "Library" / "Group Containers" / std::string_view(APP_GROUP_ID)
            / std::string_view(CONFIG_FILE_NAME))
            .string();
}

std::string logs_directory(std::string_view home_dir) {
    return (std::filesystem::path(home_dir) / "Library" / "Group Containers" / std::string_view(APP_GROUP_ID)
            / std::string_view(APP_GROUP_LOGS_DIR))
            .string();
}

std::string installed_bundle_path(std::string_view applications_dir) {
    return (std::filesystem::path(applications_dir) / std::string_view(APP_BUNDLE_NAME)).string();
}

std::string resolve_app_bundle(
        std::optional<std::string_view> env_override, std::string_view binary_dir, std::string_view applications_dir) {
    if (env_override.has_value() && is_existing_directory(*env_override)) {
        return std::string(*env_override);
    }
    std::string sibling = (std::filesystem::path(binary_dir) / std::string_view(APP_BUNDLE_NAME)).string();
    if (is_existing_directory(sibling)) {
        return sibling;
    }
    std::string installed = installed_bundle_path(applications_dir);
    if (is_existing_directory(installed)) {
        return installed;
    }
    return {};
}

std::string binary_dir() {
    std::error_code ec;
    std::filesystem::path executable;
#if defined(__APPLE__)
    uint32_t size = 0;
    if (_NSGetExecutablePath(nullptr, &size) != 0) {
        std::vector<char> buffer(size);
        if (_NSGetExecutablePath(buffer.data(), &size) == 0) {
            executable = buffer.data();
        }
    }
#elif defined(__linux__)
    std::vector<char> buffer(PATH_MAX);
    const ssize_t length = readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
    if (length > 0) {
        buffer[length] = '\0';
        executable = buffer.data();
    }
#elif defined(_WIN32)
    std::vector<char> buffer(MAX_PATH);
    const DWORD length = GetModuleFileNameA(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length > 0 && length < buffer.size()) {
        buffer[length] = '\0';
        executable = buffer.data();
    }
#endif
    if (executable.empty()) {
        return {};
    }
    std::filesystem::path canonical = std::filesystem::weakly_canonical(executable, ec);
    if (ec) {
        return {};
    }
    return canonical.parent_path().string();
}

std::string bundle_version(std::string_view bundle_path) {
#if defined(__APPLE__)
    CFStringRef path_string =
            CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault, std::string(bundle_path).c_str());
    if (path_string == nullptr) {
        return {};
    }
    CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path_string, kCFURLPOSIXPathStyle, true);
    CFRelease(path_string);
    if (url == nullptr) {
        return {};
    }
    CFBundleRef bundle = CFBundleCreate(kCFAllocatorDefault, url);
    CFRelease(url);
    if (bundle == nullptr) {
        return {};
    }
    std::string version;
    // The returned value is not owned by the caller.
    auto *short_version =
            static_cast<CFStringRef>(CFBundleGetValueForInfoDictionaryKey(bundle, CFSTR("CFBundleShortVersionString")));
    if (short_version != nullptr) {
        if (const char *cstr = CFStringGetCStringPtr(short_version, kCFStringEncodingUTF8); cstr != nullptr) {
            version = cstr;
        } else {
            char buffer[256];
            if (CFStringGetCString(short_version, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                version = buffer;
            }
        }
    }
    CFRelease(bundle);
    return version;
#else
    (void) bundle_path;
    return {};
#endif
}

std::optional<std::string> stage_app_bundle(
        std::string_view source_bundle, std::string_view applications_dir, std::string &error) {
    namespace fs = std::filesystem;
    const fs::path source(source_bundle);
    const fs::path destination = installed_bundle_path(applications_dir);

    if (!is_existing_directory(source.string())) {
        error = "source app bundle is missing: " + source.string();
        return std::nullopt;
    }

    std::error_code ec;
    if (fs::exists(destination, ec)) {
        const std::string installed_version = bundle_version(destination.string());
        if (!installed_version.empty() && installed_version == bundle_version(source.string())) {
            return destination.string();
        }
        fs::remove_all(destination, ec);
        if (ec) {
            error = "failed to remove the installed app bundle " + destination.string() + ": " + ec.message();
            return std::nullopt;
        }
    }

    fs::copy(source, destination, fs::copy_options::recursive | fs::copy_options::copy_symlinks, ec);
    if (ec) {
        error = "failed to copy the app bundle into " + destination.string() + ": " + ec.message()
                + " (try running with sudo)";
        return std::nullopt;
    }
    return destination.string();
}

std::vector<std::string> app_spawn_arguments(
        std::string_view bundle_path, Command command, std::string_view config_path) {
    std::vector<std::string> arguments;
    arguments.push_back(
            (std::filesystem::path(bundle_path) / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string());
    arguments.emplace_back(command_name(command));
    if (command == Command::start) {
        arguments.emplace_back("--config");
        arguments.emplace_back(config_path);
    }
    return arguments;
}

int spawn_app(const std::vector<std::string> &arguments) {
#if defined(__APPLE__)
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
        return -1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        const int code = sys::last_error();
        errlog(g_logger, "Failed to wait for '{}': {} ({})", argv.front(), sys::strerror(code), code);
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        errlog(g_logger, "'{}' was killed by signal {}", argv.front(), WTERMSIG(status));
    }
    return -1;
#else
    (void) arguments;
    errlog(g_logger, "Spawning the host app is only supported on macOS");
    return -1;
#endif
}

void print_log_tails(std::string_view home_dir, std::size_t max_lines) {
    const std::filesystem::path logs_dir(logs_directory(home_dir));
    for (const std::string_view base_name : {std::string_view("app"), std::string_view("extension")}) {
        const std::filesystem::path log_file = logs_dir / (std::string(base_name) + ".log");
        std::ifstream file(log_file);
        if (!file) {
            continue;
        }
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(file, line)) {
            // Log records are separated with a trailing `RS` (\x1E) byte.
            if (!line.empty() && line.back() == '\x1E') {
                line.pop_back();
            }
            if (!line.empty()) {
                lines.push_back(std::move(line));
            }
        }
        if (lines.empty()) {
            continue;
        }
        std::fprintf(stderr, "--- last lines of %s ---\n", log_file.string().c_str());
        const std::size_t begin = lines.size() > max_lines ? lines.size() - max_lines : 0;
        for (std::size_t i = begin; i < lines.size(); ++i) {
            std::fprintf(stderr, "%s\n", lines[i].c_str());
        }
    }
}

bool validate_sysext_config(std::string_view config_path) {
    toml::parse_result parse_result = toml::parse_file(config_path);
    if (!parse_result) {
        errlog(g_logger, "Failed parsing configuration: {}", parse_result.error().description());
        return false;
    }
    const toml::table *listener = parse_result.table()["listener"].as_table();
    const toml::table *tun = listener != nullptr ? (*listener)["tun"].as_table() : nullptr;
    if (tun != nullptr) {
        return true;
    }
    if (listener != nullptr && (*listener)["socks"].as_table() != nullptr) {
        errlog(g_logger,
                "A socks-only configuration cannot be used in --sysext mode: "
                "the system extension requires a [listener.tun] section");
    } else {
        errlog(g_logger, "--sysext mode requires a [listener.tun] section in the configuration");
    }
    return false;
}

/// Apply the command line log level like the other CLI modes do.
static bool apply_sysext_loglevel(const cxxopts::ParseResult &cli_args) {
    auto loglevel = TrustTunnelCliUtils::parse_loglevel(cli_args["loglevel"].as<std::string>());
    if (!loglevel) {
        errlog(g_logger, "Unexpected log level: {}", cli_args["loglevel"].as<std::string>());
        return false;
    }
    Logger::set_log_level(*loglevel);
    return true;
}

/// Copy the configuration into the app group container so the sandboxed host app can read it.
static bool copy_config_to_container(std::string_view config_path, std::string_view container_config_path) {
    std::error_code ec;
    const std::filesystem::path container_dir = std::filesystem::path(container_config_path).parent_path();
    std::filesystem::create_directories(container_dir, ec);
    if (ec) {
        errlog(g_logger, "Failed to create the app group container directory {}: {}", container_dir.string(),
                ec.message());
        return false;
    }
    std::filesystem::copy_file(
            config_path, container_config_path, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        errlog(g_logger, "Failed to copy the configuration into {}: {}", container_config_path, ec.message());
        return false;
    }
    infolog(g_logger, "The configuration has been copied to {}", container_config_path);
    return true;
}

/// Resolve the host app bundle without staging it. Returns `std::nullopt` when nothing is found.
static std::optional<std::string> resolve_host_app() {
    const char *override_path = std::getenv(APP_PATH_ENV_VAR.data());
    std::optional<std::string_view> env_override;
    if (override_path != nullptr && *override_path != '\0') {
        env_override = std::string_view(override_path);
    }
    std::string resolved = resolve_app_bundle(env_override, binary_dir());
    if (env_override.has_value() && resolved != *env_override) {
        warnlog(g_logger, "{} points to a missing directory, ignoring it", APP_PATH_ENV_VAR);
    }
    if (resolved.empty()) {
        return std::nullopt;
    }
    return resolved;
}

/// Locate the host app bundle and ensure the copy in the applications directory is up to
/// date, stopping the tunnel via the installed copy before a version replacement.
static std::optional<std::string> stage_host_app() {
    std::optional<std::string> source = resolve_host_app();
    if (!source) {
        errlog(g_logger,
                "The host app bundle '{}' was not found: set {}, place it next to the client binary "
                "or install it first",
                APP_BUNDLE_NAME, APP_PATH_ENV_VAR);
        return std::nullopt;
    }
    std::string installed = installed_bundle_path();
    if (installed == *source) {
        return installed;
    }

    std::error_code ec;
    if (std::filesystem::exists(installed, ec) && !ec && bundle_version(installed) != bundle_version(*source)) {
        infolog(g_logger, "The installed host app differs from {}, stopping the tunnel before the replacement",
                *source);
        const int stop_exit = spawn_app(app_spawn_arguments(installed, Command::stop, {}));
        if (stop_exit != 0) {
            warnlog(g_logger, "Failed to stop the tunnel via the installed host app (exit status {})", stop_exit);
        }
    }

    std::string error;
    std::optional<std::string> staged = stage_app_bundle(*source, DEFAULT_APPLICATIONS_DIR, error);
    if (!staged) {
        errlog(g_logger, "Failed to stage the host app: {}", error);
        return std::nullopt;
    }
    dbglog(g_logger, "The host app is staged at {}", *staged);
    return staged;
}

int run_sysext(const cxxopts::ParseResult &cli_args) {
    if (!apply_sysext_loglevel(cli_args)) {
        return 1;
    }

    std::optional<Command> command;
    if (cli_args.count("command") > 0) {
        command = parse_command(cli_args["command"].as<std::string>());
        if (!command) {
            errlog(g_logger,
                    "Unknown --sysext subcommand '{}', expected one of: install, start, stop, status, uninstall",
                    cli_args["command"].as<std::string>());
            return 1;
        }
    } else {
        errlog(g_logger, "A --sysext subcommand is required, one of: install, start, stop, status, uninstall");
        return 1;
    }

    const char *home = std::getenv("HOME");
    if (home == nullptr || *home == '\0') {
        errlog(g_logger, "HOME environment variable is not set");
        return 1;
    }
    const std::string_view home_dir = home;

    std::string app_config_path;
    if (*command == Command::start) {
        app_config_path = cli_args["config"].as<std::string>();
        if (!validate_sysext_config(app_config_path)) {
            return 1;
        }
        // Hand the config to the sandboxed host app through the app group container.
        std::string container_config = container_config_path(home_dir);
        if (!copy_config_to_container(app_config_path, container_config)) {
            return 1;
        }
        app_config_path = std::move(container_config);
    }

    const bool stages_bundle = *command == Command::install || *command == Command::start;
    std::optional<std::string> app_bundle = stages_bundle ? stage_host_app() : resolve_host_app();
    if (!app_bundle) {
        if (*command == Command::status) {
            infolog(g_logger, "The TrustTunnel system extension is not installed");
            return 0;
        }
        if (*command == Command::uninstall) {
            infolog(g_logger, "The TrustTunnel system extension host app is not installed, nothing to uninstall");
            return 0;
        }
        errlog(g_logger, "The host app bundle is not installed, cannot stop the tunnel");
        return 1;
    }

    const std::vector<std::string> app_arguments = app_spawn_arguments(*app_bundle, *command, app_config_path);
    dbglog(g_logger, "Spawning '{}'", app_arguments.front());
    const int app_exit = spawn_app(app_arguments);
    if (app_exit == -1) {
        errlog(g_logger, "Failed to spawn the host app '{}'", app_arguments.front());
        return 1;
    }
    if (app_exit != 0) {
        errlog(g_logger, "The host app failed with exit status {}", app_exit);
        print_log_tails(home_dir, LOG_TAIL_LINES);
        return 1;
    }

    const std::string logs_dir = logs_directory(home_dir);
    switch (*command) {
    case Command::start:
        infolog(g_logger, "The tunnel start has been submitted, check the state with --sysext status; logs: {}",
                logs_dir);
        break;
    case Command::status:
        infolog(g_logger, "Logs: {}", logs_dir);
        break;
    case Command::uninstall: {
        std::error_code ec;
        const std::string installed = installed_bundle_path();
        if (std::filesystem::exists(installed, ec) && !ec) {
            std::filesystem::remove_all(installed, ec);
            if (ec) {
                errlog(g_logger, "Failed to remove the host app bundle {}: {} (try running with sudo)", installed,
                        ec.message());
                return 1;
            }
        }
        break;
    }
    default:
        break;
    }
    return 0;
}

} // namespace ag::sysext
