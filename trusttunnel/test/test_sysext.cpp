#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#if defined(__APPLE__) && !TARGET_OS_IPHONE

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "vpn/trusttunnel/sysext.h"
#include "vpn/trusttunnel/trusttunnel_sysext.h"

namespace fs = std::filesystem;

using ag::TrustTunnelSysextController;

static constexpr std::string_view APP_BUNDLE_NAME = ag::TRUSTTUNNEL_SYSEXT_BUNDLE_NAME;
static constexpr std::string_view APP_BINARY_NAME = ag::TRUSTTUNNEL_SYSEXT_BINARY_NAME;

/**
 * Process runner that records every call and returns a preset result, so the tests observe
 * the spawned commands without running any real process.
 */
class MockProcessRunner final : public ag::ProcessRunner {
public:
    std::optional<int> run(const std::vector<std::string> &argv) override {
        m_calls.push_back(argv);
        return m_exit_status;
    }

    /// The argv of every run() call so far, in call order.
    const std::vector<std::vector<std::string>> &calls() const {
        return m_calls;
    }

    /// Set the result returned by the following run() calls; `std::nullopt` emulates a
    /// process that could not be spawned.
    void set_exit_status(std::optional<int> exit_status) {
        m_exit_status = exit_status;
    }

private:
    std::vector<std::vector<std::string>> m_calls;
    std::optional<int> m_exit_status = 0;
};

/**
 * Black-box tests of the `--sysext` mode: the controller is driven through `run()` against
 * bundle paths in temporary directories and a mock process runner. Only behavior observable
 * from outside is checked.
 */
class SysextTest : public testing::Test {
protected:
    void SetUp() override {
        // A unique root per test so parallel ctest invocations do not share directories.
        const testing::TestInfo *test_info = testing::UnitTest::GetInstance()->current_test_info();
        m_root = fs::temp_directory_path() / ("tt_sysext_test_" + std::string(test_info->name()));
        std::error_code ec;
        fs::remove_all(m_root, ec);
        m_binary_dir = make_dir("binary");
        m_applications_dir = make_dir("applications");
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(m_root, ec);
    }

    /// Construct a controller over the fixture bundle paths with the given process runner.
    TrustTunnelSysextController make_controller(std::unique_ptr<ag::ProcessRunner> runner) const {
        return {m_binary_dir / APP_BUNDLE_NAME, m_applications_dir / APP_BUNDLE_NAME, std::move(runner)};
    }

    /// Construct a controller with a mock process runner; the runner keeps recording calls
    /// through the raw pointer stored in the fixture.
    TrustTunnelSysextController make_controller() {
        auto runner = std::make_unique<MockProcessRunner>();
        m_runner = runner.get();
        return make_controller(std::move(runner));
    }

    /// Create a host app bundle in the given parent directory and return its path.
    fs::path make_bundle(const fs::path &parent) {
        std::error_code ec;
        const fs::path bundle = parent / std::string_view(APP_BUNDLE_NAME);
        fs::create_directories(bundle / "Contents" / "MacOS", ec);
        // The empty file completes the bundle shape; the test that spawns for real replaces
        // it with a script.
        std::ofstream binary(bundle / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME));
        return bundle;
    }

    /// Write the given content to a configuration file and return its path.
    fs::path write_config(std::string_view name, std::string_view content) {
        const fs::path dir = make_dir("config");
        const fs::path path = dir / name;
        std::ofstream file(path);
        file << content;
        return path;
    }

    fs::path m_root;
    fs::path m_binary_dir;
    fs::path m_applications_dir;
    MockProcessRunner *m_runner = nullptr;

private:
    /// Create a directory under the test root.
    fs::path make_dir(std::string_view name) {
        std::error_code ec;
        const fs::path path = m_root / name;
        fs::create_directories(path, ec);
        return path;
    }
};

static constexpr std::string_view SOCKS_ONLY_CONFIG = R"toml(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]

[listener.socks]
address = "127.0.0.1:1080"
)toml";

static constexpr std::string_view TUN_CONFIG = R"toml(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]

[listener.tun]
mtu_size = 1350
)toml";

TEST_F(SysextTest, RequiresSubcommand) {
    TrustTunnelSysextController controller = make_controller();
    EXPECT_FALSE(controller.run("", {}));
    EXPECT_TRUE(m_runner->calls().empty());
}

TEST_F(SysextTest, ForwardsUnknownSubcommandToTheApp) {
    const fs::path installed = make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_TRUE(controller.run("frobnicate", {}));
    ASSERT_EQ(m_runner->calls().size(), 1u);
    const std::vector<std::string> expected = {
            (installed / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string(), "frobnicate"};
    EXPECT_EQ(m_runner->calls().front(), expected);
}

TEST_F(SysextTest, StartPassesOriginalConfigPath) {
    // A deliberately socks-only configuration: nothing validates it anymore, a bad config
    // surfaces as a host-app failure relayed through the exit status.
    const fs::path config = write_config("socks.toml", SOCKS_ONLY_CONFIG);
    make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_TRUE(controller.run("start", config.string()));
    ASSERT_EQ(m_runner->calls().size(), 1u);
    const fs::path installed = m_applications_dir / std::string_view(APP_BUNDLE_NAME);
    const std::vector<std::string> expected = {
            (installed / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string(), "start", "--config",
            config.string()};
    EXPECT_EQ(m_runner->calls().front(), expected);

    // The configuration is not copied anywhere.
    std::vector<fs::path> toml_files;
    for (const fs::path &entry : fs::recursive_directory_iterator(m_root)) {
        if (entry.extension() == ".toml") {
            toml_files.push_back(entry);
        }
    }
    ASSERT_EQ(toml_files.size(), 1u);
    EXPECT_EQ(toml_files.front(), config);
}

TEST_F(SysextTest, StatusFailsWithoutInstalledApp) {
    TrustTunnelSysextController controller = make_controller();
    EXPECT_FALSE(controller.run("status", {}));
    EXPECT_TRUE(m_runner->calls().empty());
}

TEST_F(SysextTest, UninstallFailsWithoutInstalledApp) {
    TrustTunnelSysextController controller = make_controller();
    EXPECT_FALSE(controller.run("uninstall", {}));
    EXPECT_TRUE(m_runner->calls().empty());
}

TEST_F(SysextTest, StatusRelaysToTheApp) {
    const fs::path installed = make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_TRUE(controller.run("status", {}));
    ASSERT_EQ(m_runner->calls().size(), 1u);
    const std::vector<std::string> expected = {
            (installed / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string(), "status"};
    EXPECT_EQ(m_runner->calls().front(), expected);
}

TEST_F(SysextTest, StopRelaysToTheApp) {
    const fs::path installed = make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_TRUE(controller.run("stop", {}));
    ASSERT_EQ(m_runner->calls().size(), 1u);
    const std::vector<std::string> expected = {
            (installed / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string(), "stop"};
    EXPECT_EQ(m_runner->calls().front(), expected);
}

TEST_F(SysextTest, RelaysAppExitStatus) {
    make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    m_runner->set_exit_status(1);
    EXPECT_FALSE(controller.run("status", {}));
}

TEST_F(SysextTest, ReportsSpawnFailure) {
    make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    m_runner->set_exit_status(std::nullopt);
    EXPECT_FALSE(controller.run("status", {}));
}

TEST_F(SysextTest, InstallReplacesInstalledBundle) {
    make_bundle(m_binary_dir);
    const fs::path installed = make_bundle(m_applications_dir);
    const fs::path marker = installed / "Contents" / "marker";
    {
        std::ofstream file(marker);
        file << "stale";
    }
    TrustTunnelSysextController controller = make_controller();
    EXPECT_TRUE(controller.run("install", {}));
    const std::string installed_binary =
            (installed / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string();
    const std::vector<std::string> expected_install = {installed_binary, "install"};
    ASSERT_EQ(m_runner->calls().size(), 1u);
    EXPECT_EQ(m_runner->calls()[0], expected_install);
    // The installed bundle has been replaced with the sibling one.
    std::error_code ec;
    EXPECT_FALSE(fs::exists(marker, ec));
}

TEST_F(SysextTest, InstallFromInstallLocationDoesNotReplaceItself) {
    const fs::path bundle = make_bundle(m_applications_dir);
    auto runner = std::make_unique<MockProcessRunner>();
    m_runner = runner.get();
    TrustTunnelSysextController controller(bundle, bundle, std::move(runner));
    EXPECT_TRUE(controller.run("install", {}));
    ASSERT_EQ(m_runner->calls().size(), 1u);
    const std::vector<std::string> expected = {
            (bundle / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string(), "install"};
    EXPECT_EQ(m_runner->calls().front(), expected);
    std::error_code ec;
    EXPECT_TRUE(fs::exists(bundle, ec));
}

TEST_F(SysextTest, StagingFailsWithoutAnyBundle) {
    const fs::path config = write_config("tun.toml", TUN_CONFIG);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_FALSE(controller.run("install", {}));
    // No bundle exists anywhere, so staging is what fails, before any spawn.
    EXPECT_FALSE(controller.run("start", config.string()));
    EXPECT_TRUE(m_runner->calls().empty());
}

TEST_F(SysextTest, InstallFailsWithoutShippedBundle) {
    // An already installed copy is not a staging source: install requires the shipped one.
    make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_FALSE(controller.run("install", {}));
    EXPECT_TRUE(m_runner->calls().empty());
}

TEST_F(SysextTest, RuntimeCommandsRequireInstalledApp) {
    // A shipped bundle is a staging source only: every runtime command requires the
    // installed copy.
    make_bundle(m_binary_dir);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_FALSE(controller.run("start", "config.toml"));
    EXPECT_FALSE(controller.run("stop", {}));
    EXPECT_FALSE(controller.run("status", {}));
    EXPECT_FALSE(controller.run("uninstall", {}));
    EXPECT_TRUE(m_runner->calls().empty());
}

TEST_F(SysextTest, UninstallRemovesInstalledBundle) {
    const fs::path installed = make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_TRUE(controller.run("uninstall", {}));
    ASSERT_EQ(m_runner->calls().size(), 1u);
    const std::vector<std::string> expected = {
            (installed / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string(), "uninstall"};
    EXPECT_EQ(m_runner->calls().front(), expected);
    std::error_code ec;
    EXPECT_FALSE(fs::exists(installed, ec));
}

TEST_F(SysextTest, IgnoresShippedBundleForRuntimeCommands) {
    make_bundle(m_binary_dir);
    const fs::path installed = make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_TRUE(controller.run("status", {}));
    ASSERT_EQ(m_runner->calls().size(), 1u);
    const std::vector<std::string> expected = {
            (installed / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string(), "status"};
    EXPECT_EQ(m_runner->calls().front(), expected);
}

TEST_F(SysextTest, RunsInstalledBundle) {
    const fs::path installed = make_bundle(m_applications_dir);
    TrustTunnelSysextController controller = make_controller();
    EXPECT_TRUE(controller.run("status", {}));
    ASSERT_EQ(m_runner->calls().size(), 1u);
    const std::vector<std::string> expected = {
            (installed / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME)).string(), "status"};
    EXPECT_EQ(m_runner->calls().front(), expected);
}

TEST_F(SysextTest, DefaultInstallLocationIsUnderApplications) {
    EXPECT_EQ(ag::default_install_location(), fs::path("/Applications") / std::string_view(APP_BUNDLE_NAME));
}

TEST_F(SysextTest, DefaultShippedBundleIsNextToTheRunningBinary) {
    EXPECT_EQ(ag::default_shipped_bundle_location(), ag::executable_dir() / std::string_view(APP_BUNDLE_NAME));
}

TEST_F(SysextTest, RealSpawnPassesArgumentsWithSpaces) {
    const fs::path bundle = make_bundle(m_applications_dir);
    const fs::path binary = bundle / "Contents" / "MacOS" / std::string_view(APP_BINARY_NAME);
    const fs::path record = m_root / "spawn-record.log";
    {
        std::ofstream script(binary);
        script << "#!/bin/sh\n";
        script << R"sh(printf '%s\n' "$0" "$@" >> ')sh" << record.string() << "'\n";
    }
    std::error_code ec;
    fs::permissions(binary, fs::perms::owner_all, ec);

    TrustTunnelSysextController controller = make_controller(std::make_unique<ag::SpawnProcessRunner>());
    EXPECT_TRUE(controller.run("status", {}));
    std::ifstream file(record);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    // The binary path travels as one argv element with no shell in between.
    ASSERT_EQ(lines.size(), 2u);
    EXPECT_EQ(lines[0], binary.string());
    EXPECT_EQ(lines[1], "status");
}

#endif // defined(__APPLE__) && !TARGET_OS_IPHONE
