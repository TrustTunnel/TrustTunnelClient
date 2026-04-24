#include "vpn/vpn_easy.h"
#include "vpn/vpn_easy_service.h"
#include "vpn/vpn.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <fmt/format.h>
#include <magic_enum/magic_enum.hpp>

#include "common/logger.h"

static constexpr const wchar_t *SERVICE_NAME = L"vpn_easy_service";
static constexpr const wchar_t *PIPE_NAME = L"\\\\.\\pipe\\TestPipeName";

static void state_changed_cb(void *, int state) {
    fmt::println(stderr, "VPN state changed: ({}) {}",
            state, magic_enum::enum_name(static_cast<ag::VpnSessionState>(state)));
}

/// Read config.toml into a string. Return empty string on failure.
static std::string read_config() {
    std::ifstream in("config.toml");
    std::stringstream buf;
    buf << in.rdbuf();
    if (in.fail()) {
        fmt::println(stderr, "Failed to read config.toml");
        return {};
    }
    return buf.str();
}

/// Install the service. If it already exists, uninstall first and retry.
static int32_t install_service() {
    auto image = absolute(std::filesystem::path(".") / "vpn_easy_service.exe").wstring();
    auto logfile = absolute(std::filesystem::path(".") / "vpn_easy_service.log").wstring();

    int32_t ret = vpn_easy_service_install(
            image.c_str(), logfile.c_str(), PIPE_NAME, SERVICE_NAME, L"VPN easy service", L"Test description");
    if (ret == VPN_EASY_SVC_ERR_SERVICE_EXISTS) {
        fmt::println(stderr, "Service already exists, uninstalling first...");
        vpn_easy_service_uninstall(SERVICE_NAME);
        ret = vpn_easy_service_install(
                image.c_str(), logfile.c_str(), PIPE_NAME, SERVICE_NAME, L"VPN easy service", L"Test description");
    }
    return ret;
}

/// Test install and uninstall only.
static int test_install_uninstall() {
    fmt::println(stderr, "=== test_install_uninstall ===");

    fmt::println(stderr, "Installing service...");
    int32_t ret = install_service();
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_install: {}", ret);
        return -1;
    }

    fmt::println(stderr, "Type 's' to stop");
    while (getchar() != 's') {
    }

    ret = vpn_easy_service_uninstall(SERVICE_NAME);
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_uninstall: {}", ret);
        return -1;
    }

    return 0;
}

/// Test start and stop via the pipe client (requires service to be installed already).
static int test_start_stop() {
    fmt::println(stderr, "=== test_start_stop ===");

    std::string config = read_config();
    if (config.empty()) {
        return -1;
    }

    fmt::println(stderr, "Starting service...");
    int32_t ret = vpn_easy_service_start(SERVICE_NAME, PIPE_NAME, config.c_str(),
            state_changed_cb, nullptr);
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_start: {}", ret);
        return -1;
    }
    fmt::println(stderr, "Service started. Type 's' to stop");
    while (getchar() != 's') {
    }

    fmt::println(stderr, "Stopping service...");
    ret = vpn_easy_service_stop(SERVICE_NAME, PIPE_NAME);
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_stop: {}", ret);
        return -1;
    }
    fmt::println(stderr, "Service stopped.");

    return 0;
}

/// Test full lifecycle: install, start, stop, uninstall.
static int test_full_lifecycle() {
    fmt::println(stderr, "=== test_full_lifecycle ===");

    std::string config = read_config();
    if (config.empty()) {
        return -1;
    }

    fmt::println(stderr, "Installing service...");
    int32_t ret = install_service();
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_install: {}", ret);
        return -1;
    }

    fmt::println(stderr, "Starting VPN via service...");
    ret = vpn_easy_service_start(SERVICE_NAME, PIPE_NAME, config.c_str(),
            state_changed_cb, nullptr);
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_start: {}", ret);
        vpn_easy_service_uninstall(SERVICE_NAME);
        return -1;
    }
    fmt::println(stderr, "VPN started. Type 's' to stop");
    while (getchar() != 's') {
    }

    fmt::println(stderr, "Stopping VPN via service...");
    ret = vpn_easy_service_stop(SERVICE_NAME, PIPE_NAME);
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_stop: {}", ret);
    }

    fmt::println(stderr, "Uninstalling service...");
    ret = vpn_easy_service_uninstall(SERVICE_NAME);
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_uninstall: {}", ret);
        return -1;
    }

    fmt::println(stderr, "Done.");
    return 0;
}

int main(int argc, char **argv) {
    ag::Logger::set_log_level(ag::LOG_LEVEL_DEBUG);

    const char *test = (argc > 1) ? argv[1] : "full";

    if (strcmp(test, "install") == 0) {
        return test_install_uninstall();
    }
    if (strcmp(test, "startstop") == 0) {
        return test_start_stop();
    }
    if (strcmp(test, "full") == 0) {
        return test_full_lifecycle();
    }

    fmt::println(stderr, "Usage: {} [install|startstop|full]", argv[0]);
    return 1;
}
