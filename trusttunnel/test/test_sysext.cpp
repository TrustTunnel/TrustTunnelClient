#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "vpn/trusttunnel/sysext.h"

namespace fs = std::filesystem;

using ag::sysext::app_spawn_arguments;
using ag::sysext::bundle_version;
using ag::sysext::Command;
using ag::sysext::command_name;
using ag::sysext::container_config_path;
using ag::sysext::installed_bundle_path;
using ag::sysext::logs_directory;
using ag::sysext::parse_command;
using ag::sysext::resolve_app_bundle;
using ag::sysext::stage_app_bundle;
using ag::sysext::validate_sysext_config;

static constexpr std::string_view TEST_ROOT = "./sysext-test";

/// Remove the whole test directory tree.
static void remove_test_root() {
    std::error_code ec;
    fs::remove_all(TEST_ROOT, ec);
}

/// Create a directory under the test root and return its path.
static fs::path make_dir(std::string_view name) {
    std::error_code ec;
    const fs::path path = fs::path(TEST_ROOT) / name;
    fs::create_directories(path, ec);
    return path;
}

/// Create a minimal app bundle with the given version and return its path.
static fs::path make_bundle(const fs::path &parent_dir, std::string_view version) {
    const fs::path bundle = parent_dir / std::string_view(ag::sysext::APP_BUNDLE_NAME);
    std::error_code ec;
    fs::create_directories(bundle / "Contents" / "MacOS", ec);
    {
        std::ofstream plist(bundle / "Contents" / "Info.plist");
        plist << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
              << "<plist version=\"1.0\">\n<dict>\n"
              << "\t<key>CFBundleShortVersionString</key>\n\t<string>" << version << "</string>\n"
              << "</dict>\n</plist>\n";
    }
    {
        std::ofstream binary(bundle / "Contents" / "MacOS" / std::string_view(ag::sysext::APP_BINARY_NAME));
        binary << "#!/bin/sh\n";
    }
    return bundle;
}

/// Write the given content to a file and return its path.
static fs::path write_file(const fs::path &parent_dir, std::string_view name, std::string_view content) {
    const fs::path path = parent_dir / name;
    std::ofstream file(path);
    file << content;
    return path;
}

class SysextTest : public testing::Test {
protected:
    void SetUp() override {
        remove_test_root();
    }

    void TearDown() override {
        remove_test_root();
    }
};

class SysextCommandTest : public SysextTest {};
class SysextPathTest : public SysextTest {};
class SysextSpawnArgsTest : public SysextTest {};
class SysextStageTest : public SysextTest {};
class SysextVersionTest : public SysextTest {};
class SysextConfigTest : public SysextTest {};

TEST_F(SysextCommandTest, ParsesSubcommands) {
    EXPECT_EQ(parse_command("install"), Command::install);
    EXPECT_EQ(parse_command("start"), Command::start);
    EXPECT_EQ(parse_command("stop"), Command::stop);
    EXPECT_EQ(parse_command("status"), Command::status);
    EXPECT_EQ(parse_command("uninstall"), Command::uninstall);
}

TEST_F(SysextCommandTest, RejectsUnknownNames) {
    EXPECT_EQ(parse_command(""), std::nullopt);
    EXPECT_EQ(parse_command("Install"), std::nullopt);
    EXPECT_EQ(parse_command("reinstall"), std::nullopt);
}

TEST_F(SysextCommandTest, NamesRoundTrip) {
    for (Command command : {Command::install, Command::start, Command::stop, Command::status, Command::uninstall}) {
        EXPECT_EQ(parse_command(command_name(command)), command);
    }
}

TEST_F(SysextPathTest, AppGroupPaths) {
    EXPECT_EQ(container_config_path("/Users/test"),
            "/Users/test/Library/Group Containers/group.com.adguard.TrustTunnel/config.toml");
    EXPECT_EQ(logs_directory("/Users/test"), "/Users/test/Library/Group Containers/group.com.adguard.TrustTunnel/logs");
}

TEST_F(SysextPathTest, InstalledBundlePath) {
    EXPECT_EQ(installed_bundle_path("/Applications"), "/Applications/TrustTunnel CLI System Extension Manager.app");
}

TEST_F(SysextPathTest, PrefersEnvOverride) {
    const fs::path applications = make_dir("apps");
    const fs::path env_bundle = make_bundle(make_dir("env"), "1.0.0");
    EXPECT_EQ(resolve_app_bundle(env_bundle.string(), make_dir("bin").string(), applications.string()),
            env_bundle.string());
}

TEST_F(SysextPathTest, FallsBackToSiblingBundle) {
    const fs::path applications = make_dir("apps");
    const fs::path binary_dir = make_dir("bin");
    const fs::path sibling = make_bundle(binary_dir, "1.0.0");
    EXPECT_EQ(resolve_app_bundle(std::nullopt, binary_dir.string(), applications.string()), sibling.string());
}

TEST_F(SysextPathTest, FallsBackToInstalledBundle) {
    const fs::path applications = make_dir("apps");
    const fs::path installed = make_bundle(applications, "1.0.0");
    EXPECT_EQ(resolve_app_bundle(std::nullopt, make_dir("bin").string(), applications.string()), installed.string());
}

TEST_F(SysextPathTest, ReturnsEmptyWhenNothingFound) {
    const std::string binary_dir = make_dir("bin").string();
    const std::string applications = make_dir("apps").string();
    EXPECT_TRUE(resolve_app_bundle(std::nullopt, binary_dir, applications).empty());
    EXPECT_TRUE(resolve_app_bundle(std::string_view("./sysext-test/missing"), binary_dir, applications).empty());
}

TEST_F(SysextSpawnArgsTest, BuildsArgumentsWithSpaces) {
    const std::vector<std::string> start_arguments = app_spawn_arguments(
            "/Applications/TrustTunnel CLI System Extension Manager.app", Command::start, "/tmp/config.toml");
    ASSERT_EQ(start_arguments.size(), 4);
    EXPECT_EQ(start_arguments[0],
            "/Applications/TrustTunnel CLI System Extension Manager.app/Contents/MacOS/"
            "TrustTunnel CLI System Extension Manager");
    EXPECT_EQ(start_arguments[1], "start");
    EXPECT_EQ(start_arguments[2], "--config");
    EXPECT_EQ(start_arguments[3], "/tmp/config.toml");

    const std::vector<std::string> stop_arguments =
            app_spawn_arguments("/some/App.app", Command::stop, std::string_view{});
    ASSERT_EQ(stop_arguments.size(), 2);
    EXPECT_EQ(stop_arguments[0], "/some/App.app/Contents/MacOS/TrustTunnel CLI System Extension Manager");
    EXPECT_EQ(stop_arguments[1], "stop");
}

#ifdef __APPLE__

TEST_F(SysextVersionTest, ReadsBundleVersion) {
    const fs::path bundle = make_bundle(make_dir("bundle"), "1.2.3");
    EXPECT_EQ(bundle_version(bundle.string()), "1.2.3");
    EXPECT_TRUE(bundle_version((fs::path(TEST_ROOT) / "missing.app").string()).empty());
}

TEST_F(SysextStageTest, CopiesWhenMissing) {
    const fs::path source = make_bundle(make_dir("source"), "1.0.0");
    const fs::path applications = make_dir("apps");
    std::string error;
    std::optional<std::string> staged = stage_app_bundle(source.string(), applications.string(), error);
    ASSERT_TRUE(staged.has_value()) << error;
    EXPECT_EQ(*staged, (applications / std::string_view(ag::sysext::APP_BUNDLE_NAME)).string());
    EXPECT_EQ(bundle_version(*staged), "1.0.0");
}

TEST_F(SysextStageTest, SkipsSameVersion) {
    const fs::path source = make_bundle(make_dir("source"), "1.0.0");
    const fs::path applications = make_dir("apps");
    const fs::path installed = make_bundle(applications, "1.0.0");
    const fs::path marker = write_file(installed, "marker.txt", "keep");
    std::string error;
    std::optional<std::string> staged = stage_app_bundle(source.string(), applications.string(), error);
    ASSERT_TRUE(staged.has_value()) << error;
    EXPECT_EQ(*staged, installed.string());
    // The installed copy must be left untouched.
    std::error_code ec;
    EXPECT_TRUE(fs::exists(marker, ec));
}

TEST_F(SysextStageTest, ReplacesDifferentVersion) {
    const fs::path source = make_bundle(make_dir("source"), "2.0.0");
    const fs::path applications = make_dir("apps");
    const fs::path installed = make_bundle(applications, "1.0.0");
    const fs::path marker = write_file(installed, "marker.txt", "gone");
    std::string error;
    std::optional<std::string> staged = stage_app_bundle(source.string(), applications.string(), error);
    ASSERT_TRUE(staged.has_value()) << error;
    std::error_code ec;
    EXPECT_FALSE(fs::exists(marker, ec));
    // Read the copied Info.plist directly: CFBundle caches the bundle info dictionary by URL
    // for the lifetime of the process, so reading the same path twice would see stale data.
    std::ifstream plist(fs::path(*staged) / "Contents" / "Info.plist");
    std::string content((std::istreambuf_iterator<char>(plist)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("2.0.0"), std::string::npos);
}

#endif // __APPLE__

TEST_F(SysextConfigTest, AcceptsTunListener) {
    const fs::path config = write_file(make_dir("config"), "tun.toml", R"toml(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]

[listener.tun]
mtu_size = 1350
)toml");
    EXPECT_TRUE(validate_sysext_config(config.string()));
}

TEST_F(SysextConfigTest, RejectsSocksOnlyListener) {
    const fs::path config = write_file(make_dir("config"), "socks.toml", R"toml(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]

[listener.socks]
address = "127.0.0.1:1080"
)toml");
    EXPECT_FALSE(validate_sysext_config(config.string()));
}

TEST_F(SysextConfigTest, RejectsMissingListener) {
    const fs::path config = write_file(make_dir("config"), "no-listener.toml", R"toml(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
)toml");
    EXPECT_FALSE(validate_sysext_config(config.string()));
}

TEST_F(SysextConfigTest, RejectsMissingFile) {
    EXPECT_FALSE(validate_sysext_config("./sysext-test/missing.toml"));
}
