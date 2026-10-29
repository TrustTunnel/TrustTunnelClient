#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cxxopts.hpp>

namespace ag::sysext {

/// Name of the host app bundle staged into `/Applications`.
inline constexpr std::string_view APP_BUNDLE_NAME = "TrustTunnel CLI System Extension Manager.app";
/// Name of the host app executable inside the bundle (contains spaces - never pass through a shell).
inline constexpr std::string_view APP_BINARY_NAME = "TrustTunnel CLI System Extension Manager";
/// Default directory the host app bundle is staged into.
inline constexpr std::string_view DEFAULT_APPLICATIONS_DIR = "/Applications";
/// App group shared between the host app and the system extension.
inline constexpr std::string_view APP_GROUP_ID = "group.com.adguard.TrustTunnel";
/// Environment variable overriding the location of the host app bundle (development builds).
inline constexpr std::string_view APP_PATH_ENV_VAR = "TRUSTTUNNEL_SYSEXT_APP_PATH";

/// Subcommands accepted by the CLI in `--sysext` mode.
enum class Command {
    install,
    start,
    stop,
    status,
    uninstall,
};

/// Parse a `--sysext` subcommand name. Returns `std::nullopt` for unknown names.
std::optional<Command> parse_command(std::string_view name);

/// Get the name of a `--sysext` subcommand.
std::string_view command_name(Command command);

/// Return the path of the config copy inside the app group container of the given home directory.
std::string container_config_path(std::string_view home_dir);

/// Return the logs directory inside the app group container of the given home directory.
std::string logs_directory(std::string_view home_dir);

/// Return the path of the host app bundle inside the given applications directory.
std::string installed_bundle_path(std::string_view applications_dir = DEFAULT_APPLICATIONS_DIR);

/// Resolve the host app bundle to run: development environment override, then the release
/// layout next to the CLI binary, then the installed copy in the applications directory.
/// Returns an empty string when no candidate exists.
std::string resolve_app_bundle(std::optional<std::string_view> env_override, std::string_view binary_dir,
        std::string_view applications_dir = DEFAULT_APPLICATIONS_DIR);

/// Return the directory containing the running CLI executable, or an empty string on failure.
std::string binary_dir();

/// Read the bundle's `CFBundleShortVersionString`. Returns an empty string when the bundle
/// does not exist or carries no version.
std::string bundle_version(std::string_view bundle_path);

/// Copy the source bundle into the applications directory unless a copy with the same
/// version is already installed there. Returns the path of the staged bundle on success,
/// `std::nullopt` on failure with `error` set to the reason.
std::optional<std::string> stage_app_bundle(
        std::string_view source_bundle, std::string_view applications_dir, std::string &error);

/// Build the argument list for the host app binary of the given bundle. The config path is
/// passed only to `start`, which reads the config copy from the app group container.
std::vector<std::string> app_spawn_arguments(
        std::string_view bundle_path, Command command, std::string_view config_path);

/// Run the host app with the given arguments, relaying its standard streams. Returns the
/// exit status of the app process, or -1 when it could not be spawned (the reason is logged).
int spawn_app(const std::vector<std::string> &arguments);

/// Print the tails of the host app and extension log files from the app group container.
/// The file names must stay in sync with `FileLogger.appBaseName`/`extensionBaseName`
/// in `platform/apple/TrustTunnelClient/FileLogger.swift`.
void print_log_tails(std::string_view home_dir, std::size_t max_lines);

/// Validate that the configuration can be used in `--sysext` mode: the `[listener.tun]`
/// table must be present, since the system extension runs a TUN listener. Returns true when
/// the configuration is usable, logging the reason otherwise.
bool validate_sysext_config(std::string_view config_path);

/// Entry point of the CLI `--sysext` mode: validates the configuration (for `start`),
/// stages the host app bundle, spawns the app with the subcommand and relays its result.
/// Returns the process exit status.
int run_sysext(const cxxopts::ParseResult &cli_args);

} // namespace ag::sysext
