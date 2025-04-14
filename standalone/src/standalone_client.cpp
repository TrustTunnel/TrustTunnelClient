#include <atomic>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <cxxopts.hpp>
#include <toml++/toml.h>

#include "common/logger.h"
#include "vpn/standalone/client.h"
#include "vpn/standalone/config.h"

#ifdef __APPLE__
#include "AppleSleepNotifier.h"
#endif

static constexpr std::string_view DEFAULT_CONFIG_FILE = "standalone_client.toml";

using namespace ag;

static const ag::Logger g_logger("STANDALONE_CLIENT_APP");
static std::atomic_bool keep_running{true};
static std::condition_variable g_waiter;
static std::mutex g_waiter_mutex;
static VpnStandaloneClient *g_client;

static void sighandler(int sig) {
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (g_client) {
#ifndef _WIN32
        if (sig == SIGHUP) {
            g_client->notify_network_change(ag::VPN_NS_NOT_CONNECTED);
            std::thread t([]() {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                g_client->notify_network_change(ag::VPN_NS_CONNECTED);
            });
            t.detach();
            return;
        }
#endif
        keep_running = false;
        g_waiter.notify_all();
    } else {
        exit(1);
    }
}

static void setup_sighandler() {
#ifdef _WIN32
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
#else
    signal(SIGPIPE, SIG_IGN);
    // Block SIGINT and SIGTERM - they will be waited using sigwait().
    sigset_t sigset; // NOLINT(cppcoreguidelines-init-variables)
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);
    std::thread([sigset] {
        int signum = 0;
        while (true) {
            sigwait(&sigset, &signum);
            sighandler(signum);
        }
    }).detach();
#endif
}

int main(int argc, char **argv) {
    setup_sighandler();

    cxxopts::Options args("Standalone client", "Simple console client");
    // clang-format off
    args.add_options()
            ("s", "Skip verify certificate", cxxopts::value<bool>()->default_value("false"))
            ("c,config", "Config file name.", cxxopts::value<std::string>()->default_value(std::string(DEFAULT_CONFIG_FILE)))
            ("l,loglevel", "Logging level. Possible values: error, warn, info, debug, trace.", cxxopts::value<std::string>()->default_value("info"))
            ("help", "Print usage");
    // clang-format on

    auto result = args.parse(argc, argv);
    if (result.count("help")) {
        std::cout << args.help() << '\n';
        exit(0);
    }

    toml::parse_result parse_result = toml::parse_file(result["config"].as<std::string>());
    if (!parse_result) {
        errlog(g_logger, "Failed parsing configuration: {}", parse_result.error().description());
        exit(1);
    }

    VpnStandaloneConfig config;
    config.apply_config(parse_result.table());
    config.apply_cmd_args(result);
    config.detect_bound_if();

    vpn_post_quantum_group_set_enabled(config.post_quantum_group_enabled);

    ag::Logger::set_log_level(config.loglevel);
    g_client = new ag::VpnStandaloneClient(std::move(config));

    auto res = g_client->connect(std::chrono::seconds(30));
    if (res) {
        errlog(g_logger, "{}", res->str());
        return -1;
    }

#ifdef __APPLE__
    auto sleep_notifier = std::make_unique<AppleSleepNotifier>(
            [] { g_client->notify_sleep(); },
            [] { g_client->notify_wake(); });
#endif

    std::unique_lock<std::mutex> lock(g_waiter_mutex);
    g_waiter.wait(lock, []() {
        return !keep_running.load();
    });

#ifdef __APPLE__
    sleep_notifier.reset();
#endif

    g_client->disconnect();
    delete g_client;
    return 0;
}
