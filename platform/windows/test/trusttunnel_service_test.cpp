#include "trusttunnel/trusttunnel.h"
#include "trusttunnel/trusttunnel_service.h"
#include "vpn/vpn.h"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>

#include <fmt/format.h>
#include <magic_enum/magic_enum.hpp>

#include "common/logger.h"

static constexpr const wchar_t *SERVICE_NAME = L"trusttunnel_service";
static constexpr const wchar_t *PIPE_NAME = L"\\\\.\\pipe\\TestPipeName";

static void state_changed_cb(void *, int state) {
    fmt::println(stderr, "VPN state changed: ({}) {}", state,
            magic_enum::enum_name(static_cast<ag::VpnSessionState>(state)));
}

/// State recorder for automated scenarios.
static std::mutex g_state_mutex;
static std::condition_variable g_state_cv;
static int g_last_state = -1;

static void recording_state_changed_cb(void *, int state) {
    {
        std::scoped_lock lock{g_state_mutex};
        g_last_state = state;
    }
    g_state_cv.notify_all();
    state_changed_cb(nullptr, state);
}

static bool wait_for_state(int state, std::chrono::milliseconds timeout) {
    std::unique_lock lock{g_state_mutex};
    return g_state_cv.wait_for(lock, timeout, [&] {
        return g_last_state == state;
    });
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
    auto image = absolute(std::filesystem::path(".") / "trusttunnel_service.exe").wstring();
    auto logs_dir = absolute(std::filesystem::path(".") / "trusttunnel_service.log").wstring();
    auto ring_buffer = absolute(std::filesystem::path(".") / "test_ring_buffer.dat").wstring();

    int32_t ret = trusttunnel_service_install(image.c_str(), logs_dir.c_str(), PIPE_NAME, SERVICE_NAME,
            L"VPN easy service", L"Test description", ring_buffer.c_str());
    if (ret == TRUSTTUNNEL_SVC_ERR_SERVICE_EXISTS) {
        fmt::println(stderr, "Service already exists, uninstalling first...");
        trusttunnel_service_uninstall(SERVICE_NAME);
        ret = trusttunnel_service_install(image.c_str(), logs_dir.c_str(), PIPE_NAME, SERVICE_NAME, L"VPN easy service",
                L"Test description", ring_buffer.c_str());
    }
    return ret;
}

/// Test install and uninstall only.
static int test_install_uninstall() {
    fmt::println(stderr, "=== test_install_uninstall ===");

    fmt::println(stderr, "Installing service...");
    int32_t ret = install_service();
    if (ret) {
        fmt::println(stderr, "trusttunnel_service_install: {}", ret);
        return -1;
    }

    fmt::println(stderr, "Type 's' to stop");
    while (getchar() != 's') {
    }

    ret = trusttunnel_service_uninstall(SERVICE_NAME);
    if (ret) {
        fmt::println(stderr, "trusttunnel_service_uninstall: {}", ret);
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

    fmt::println(stderr, "Starting VPN...");
    trusttunnel_service_attach(SERVICE_NAME, PIPE_NAME, state_changed_cb, nullptr, nullptr, nullptr);
    int32_t ret = trusttunnel_service_start(config.c_str());
    if (ret) {
        fmt::println(stderr, "trusttunnel_service_start: {}", ret);
        return -1;
    }
    fmt::println(stderr, "VPN started. Type 's' to stop");
    while (getchar() != 's') {
    }

    fmt::println(stderr, "Stopping VPN...");
    ret = trusttunnel_service_stop();
    if (ret) {
        fmt::println(stderr, "trusttunnel_service_stop: {}", ret);
        return -1;
    }
    trusttunnel_service_detach();
    fmt::println(stderr, "VPN stopped.");

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
        fmt::println(stderr, "trusttunnel_service_install: {}", ret);
        return -1;
    }

    fmt::println(stderr, "Starting VPN via service...");
    trusttunnel_service_attach(SERVICE_NAME, PIPE_NAME, state_changed_cb, nullptr, nullptr, nullptr);
    ret = trusttunnel_service_start(config.c_str());
    if (ret) {
        fmt::println(stderr, "trusttunnel_service_start: {}", ret);
        trusttunnel_service_uninstall(SERVICE_NAME);
        return -1;
    }
    fmt::println(stderr, "VPN started. Type 's' to stop");
    while (getchar() != 's') {
    }

    fmt::println(stderr, "Stopping VPN via service...");
    ret = trusttunnel_service_stop();
    if (ret) {
        fmt::println(stderr, "trusttunnel_service_stop: {}", ret);
    }
    trusttunnel_service_detach();

    fmt::println(stderr, "Uninstalling service...");
    ret = trusttunnel_service_uninstall(SERVICE_NAME);
    if (ret) {
        fmt::println(stderr, "trusttunnel_service_uninstall: {}", ret);
        return -1;
    }

    fmt::println(stderr, "Done.");
    return 0;
}

/// Test that the VPN can be started again after it has stopped, without tearing down the Windows
/// service in between. Regression for the "Service client is already active" stuck state: the
/// second start must reuse the live connection to the still-running service.
static int test_restart_after_stop() {
    fmt::println(stderr, "=== test_restart_after_stop ===");

    std::string config = read_config();
    if (config.empty()) {
        return -1;
    }

    int32_t ret = install_service();
    if (ret) {
        fmt::println(stderr, "trusttunnel_service_install: {}", ret);
        return -1;
    }

    auto cleanup = [](int code) {
        trusttunnel_service_stop();
        trusttunnel_service_detach();
        trusttunnel_service_uninstall(SERVICE_NAME);
        return code;
    };

    trusttunnel_service_attach(SERVICE_NAME, PIPE_NAME, recording_state_changed_cb, nullptr, nullptr, nullptr);

    for (int attempt = 1; attempt <= 2; ++attempt) {
        fmt::println(stderr, "Starting VPN (attempt {})...", attempt);
        ret = trusttunnel_service_start(config.c_str());
        if (ret) {
            fmt::println(stderr, "trusttunnel_service_start: {}", ret);
            if (attempt == 2) {
                fmt::println(stderr, "FAILED: a restart must not require the service to be stopped");
            }
            return cleanup(-1);
        }
        if (!wait_for_state(ag::VPN_SS_CONNECTED, std::chrono::seconds(30))) {
            fmt::println(stderr, "Timed out waiting for VPN_SS_CONNECTED");
            return cleanup(-1);
        }

        fmt::println(stderr, "Stopping VPN (attempt {})...", attempt);
        ret = trusttunnel_service_stop();
        if (ret) {
            fmt::println(stderr, "trusttunnel_service_stop: {}", ret);
            return cleanup(-1);
        }
        // The service reports the core's own DISCONNECTED; nothing is synthesized on either side.
        if (!wait_for_state(ag::VPN_SS_DISCONNECTED, std::chrono::seconds(30))) {
            fmt::println(stderr, "Timed out waiting for VPN_SS_DISCONNECTED");
            return cleanup(-1);
        }
    }

    trusttunnel_service_detach();

    fmt::println(stderr, "Uninstalling service...");
    ret = trusttunnel_service_uninstall(SERVICE_NAME);
    if (ret) {
        fmt::println(stderr, "trusttunnel_service_uninstall: {}", ret);
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
    if (strcmp(test, "restart_after_stop") == 0) {
        return test_restart_after_stop();
    }
    if (strcmp(test, "full") == 0) {
        return test_full_lifecycle();
    }

    fmt::println(stderr, "Usage: {} [install|startstop|restart_after_stop|full]", argv[0]);
    return 1;
}
