#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <optional>
#include <thread>

#include <gtest/gtest.h>

#include "common/logger.h"
#include "net/network_manager.h"
#include "vpn/event_loop.h"
#include "vpn/internal/vpn_client.h"

static std::mutex log_guard;
static std::condition_variable log_waker;
static std::string log_storage;

class TestListener : public ag::ClientListener {
public:
    TestListener() = default;
    ~TestListener() override = default;

    TestListener(const TestListener &) = delete;
    TestListener &operator=(const TestListener &) = delete;

    TestListener(TestListener &&) noexcept = delete;
    TestListener &operator=(TestListener &&) noexcept = delete;

    InitResult init(ag::VpnClient *vpn, ag::ClientHandler handler) override {
        return ClientListener::init(vpn, handler);
    }

    void deinit() override {
    }

    void complete_connect_request(uint64_t, ag::ClientConnectResult result) override {
    }

    void close_connection(uint64_t, bool, bool) override {
    }

    ssize_t send(uint64_t, const uint8_t *, size_t length) override {
        return length;
    }

    void consume(uint64_t, size_t) override {
    }
    ag::TcpFlowCtrlInfo flow_control_info(uint64_t) override {
        return {DEFAULT_SEND_BUFFER_SIZE, DEFAULT_SEND_WINDOW_SIZE};
    }
    void turn_read(uint64_t, bool) override {
    }
    int process_client_packets(ag::VpnPackets) override {
        return 0;
    }
};

struct VpnClientLive : public ::testing::Test {
    VpnClientLive() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_DEBUG);
        ag::Logger::set_callback([](ag::LogLevel level, std::string_view formatted_message) {
            ag::Logger::LOG_TO_STDERR(level, formatted_message);

            std::scoped_lock l(log_guard);
            log_storage += formatted_message;
            log_waker.notify_all();
        });
    }

    ag::DeclPtr<ag::VpnEventLoop, &ag::vpn_event_loop_destroy> ev_loop{ag::vpn_event_loop_create()};
    ag::DeclPtr<ag::VpnNetworkManager, &ag::vpn_network_manager_destroy> network_manager{ag::vpn_network_manager_get()};
    ag::vpn_client::Parameters parameters = {
            .ev_loop = this->ev_loop.get(),
            .network_manager = this->network_manager.get(),
            .handler = {client_handler, this},
            .cert_verify_handler =
                    {
                            .func =
                                    [](const char *, const sockaddr *, X509_STORE_CTX *, void *) {
                                        return 1;
                                    },
                    },
    };
    ag::VpnSettings settings = {
            .handler = {vpn_handler, this},
    };
    std::unique_ptr<ag::VpnClient> vpn = std::make_unique<ag::VpnClient>(this->parameters);
    ag::vpn_client::EndpointConnectionConfig connection_config = {
            .endpoint{ag::VpnEndpoint{
                    .address = ag::sockaddr_from_str("127.0.0.1:4433"),
                    .name = strdup("localhost"),
            }},
            .username = "premium",
            .password = "premium",
            .ip_availability = ag::IpVersionSet{}.set(),
    };
    std::list<ag::vpn_client::Event> raised_events;
    std::thread worker;
    std::mutex guard;
    std::condition_variable waker;

    void SetUp() override {
#ifndef I_DO_WANT_TO_RUN_LIVE_TESTS
        GTEST_SKIP() << "Comment me out if you want to run these tests";
#endif

        ag::vpn_network_manager_update_system_dns({{{"8.8.8.8"}}});

        ag::VpnError error = this->vpn->init(&this->settings);
        ASSERT_EQ(error.code, ag::VPN_EC_NOERROR) << error.text;
        run_event_loop();
    }

    void TearDown() override {
        if (this->vpn != nullptr) {
            ag::vpn_event_loop_submit(this->ev_loop.get(),
                    {
                            .arg = this,
                            .action =
                                    [](void *arg, ag::TaskId) {
                                        auto *self = (VpnClientLive *) arg;
                                        self->vpn->disconnect();
                                    },
                    });
            vpn_event_loop_stop(this->ev_loop.get());
            if (this->worker.joinable()) {
                this->worker.join();
            }
            this->vpn->finalize_disconnect();
            this->vpn->deinit();
        }

        log_storage.clear();
    }

    static void client_handler(void *arg, ag::vpn_client::Event what, void *) {
        auto *self = (VpnClientLive *) arg;

        std::scoped_lock lock(self->guard);
        self->raised_events.push_back(what);
        self->waker.notify_all();
    }

    static void vpn_handler(void *, ag::VpnEvent, void *) {
    }

    void run_event_loop() {
        this->worker = std::thread([loop = this->ev_loop.get()]() {
            if (0 != ag::vpn_event_loop_run(loop)) {
                abort();
            }
        });
    }

    bool wait_event(ag::vpn_client::Event what, std::chrono::seconds wait_for = std::chrono::seconds{10}) {
        std::unique_lock lock(this->guard);
        return this->waker.wait_for(lock, wait_for, [&]() {
            return this->raised_events.end() != std::find(this->raised_events.begin(), this->raised_events.end(), what);
        });
    }

    static void wait_log(std::string_view needle, std::chrono::seconds wait_for = std::chrono::seconds{10}) {
        std::unique_lock lock(log_guard);
        ASSERT_TRUE(log_waker.wait_for(lock, wait_for, [&]() {
            return log_storage.find(needle) != log_storage.npos;
        }));
    }

    template <class Result>
    std::optional<Result> run_sync_on_ev_loop(std::function<Result()> f) {
        struct Context {
            std::function<Result()> f;
            VpnClientLive *self;
            Result result;
        };

        auto ctx = std::make_unique<Context>(Context{
                .f = std::move(f),
                .self = this,
                .result = {},
        });

        if (!ag::vpn_event_loop_dispatch_sync(
                    this->ev_loop.get(),
                    [](void *arg) {
                        auto *ctx = (Context *) arg;
                        ctx->result = ctx->f();
                    },
                    ctx.get())) {
            return std::nullopt;
        }

        return std::move(ctx->result);
    }

    bool run_sync_on_ev_loop(std::function<void()> f) {
        return this
                ->run_sync_on_ev_loop<int>([f = std::move(f)]() {
                    f();
                    return 0;
                })
                .has_value();
    }
};

TEST_F(VpnClientLive, Connect) {
    std::optional error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        return this->vpn->connect(std::move(connection_config));
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    ASSERT_TRUE(this->wait_event(ag::vpn_client::EVENT_CONNECTED));
}

TEST_F(VpnClientLive, DnsBeingHealthCheckedListenBeforeConnected) {
    std::optional error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        ag::VpnError error = this->vpn->connect(std::move(connection_config));
        if (error.code != ag::VPN_EC_NOERROR) {
            return error;
        }

        const char *dns_upstream = "8.8.8.8";
        ag::VpnListenerConfig listener_config = {
                .dns_upstreams = {&dns_upstream, 1},
        };
        return this->vpn->listen(std::make_unique<TestListener>(), &listener_config);
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    ASSERT_TRUE(this->wait_event(ag::vpn_client::EVENT_CONNECTED));

    ASSERT_NO_FATAL_FAILURE(wait_log("ipv4only.arpa"));
    ASSERT_NO_FATAL_FAILURE(wait_log("DNS resolver health check succeeded"));
}

TEST_F(VpnClientLive, DnsBeingHealthCheckedListenAfterConnected) {
    std::optional error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        return this->vpn->connect(std::move(connection_config));
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    ASSERT_TRUE(this->wait_event(ag::vpn_client::EVENT_CONNECTED));
    std::this_thread::sleep_for(std::chrono::seconds{1});

    error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        const char *dns_upstream = "8.8.8.8";
        ag::VpnListenerConfig listener_config = {
                .dns_upstreams = {&dns_upstream, 1},
        };
        return this->vpn->listen(std::make_unique<TestListener>(), &listener_config);
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    ASSERT_NO_FATAL_FAILURE(wait_log("ipv4only.arpa"));
    ASSERT_NO_FATAL_FAILURE(wait_log("DNS resolver health check succeeded"));
}

TEST_F(VpnClientLive, ExclusionsUpdateDoesNotBreakDnsHealthCheck) {
    constexpr std::chrono::seconds DNS_TIMEOUT{3};

    this->connection_config.timeout = DNS_TIMEOUT;
    std::optional error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        return this->vpn->connect(std::move(this->connection_config));
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        const char *dns_upstream = "8.8.8.8";
        ag::VpnListenerConfig listener_config = {
                .dns_upstreams = {&dns_upstream, 1},
        };
        return this->vpn->listen(std::make_unique<TestListener>(), &listener_config);
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    ASSERT_TRUE(this->wait_event(ag::vpn_client::EVENT_CONNECTED));
    ASSERT_NO_FATAL_FAILURE(wait_log(";; ipv4only.arpa.\tIN\tA"));
    ASSERT_TRUE(this->run_sync_on_ev_loop([this]() {
        this->vpn->reset_connections(-1);
        this->vpn->update_exclusions(ag::VPN_MODE_SELECTIVE, "example.com");
    }));

    ASSERT_FALSE(this->wait_event(ag::vpn_client::EVENT_DNS_UPSTREAM_UNAVAILABLE, 3 * DNS_TIMEOUT / 2));
}

TEST_F(VpnClientLive, DnsUnavailableOnTimeout) {
    constexpr std::chrono::seconds DNS_TIMEOUT{3};

    this->connection_config.timeout = DNS_TIMEOUT;
    std::optional error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        return this->vpn->connect(std::move(this->connection_config));
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        const char *dns_upstream = "1.1.2.3";
        ag::VpnListenerConfig listener_config = {
                .dns_upstreams = {&dns_upstream, 1},
        };
        return this->vpn->listen(std::make_unique<TestListener>(), &listener_config);
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    ASSERT_TRUE(this->wait_event(ag::vpn_client::EVENT_CONNECTED));
    ASSERT_NO_FATAL_FAILURE(wait_log(";; ipv4only.arpa.\tIN\tA"));

    ASSERT_TRUE(this->wait_event(ag::vpn_client::EVENT_DNS_UPSTREAM_UNAVAILABLE, 3 * DNS_TIMEOUT / 2));
}

TEST_F(VpnClientLive, DisconnectDoesNotCauseDnsUnavailable) {
    constexpr std::chrono::seconds DNS_TIMEOUT{3};

    this->connection_config.timeout = DNS_TIMEOUT;
    std::optional error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        return this->vpn->connect(std::move(this->connection_config));
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        const char *dns_upstream = "8.8.8.8";
        ag::VpnListenerConfig listener_config = {
                .dns_upstreams = {&dns_upstream, 1},
        };
        return this->vpn->listen(std::make_unique<TestListener>(), &listener_config);
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    ASSERT_TRUE(this->wait_event(ag::vpn_client::EVENT_CONNECTED));
    ASSERT_NO_FATAL_FAILURE(wait_log(";; ipv4only.arpa.\tIN\tA"));

    ASSERT_TRUE(this->run_sync_on_ev_loop([this]() {
        this->vpn->disconnect();
    }));

    ASSERT_FALSE(this->wait_event(ag::vpn_client::EVENT_DNS_UPSTREAM_UNAVAILABLE, 3 * DNS_TIMEOUT / 2));
}

TEST_F(VpnClientLive, SystemDnsAbsenceDoesNotCauseDnsUnavailable) {
    constexpr std::chrono::seconds DNS_TIMEOUT{3};

    ag::vpn_network_manager_update_system_dns({});
    this->vpn->update_exclusions(ag::VPN_MODE_GENERAL, "example.com");

    this->connection_config.timeout = DNS_TIMEOUT;
    std::optional error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        return this->vpn->connect(std::move(this->connection_config));
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    error = this->run_sync_on_ev_loop<ag::VpnError>([this]() {
        const char *dns_upstream = "8.8.8.8";
        ag::VpnListenerConfig listener_config = {
                .dns_upstreams = {&dns_upstream, 1},
        };
        return this->vpn->listen(std::make_unique<TestListener>(), &listener_config);
    });
    ASSERT_TRUE(error.has_value());
    ASSERT_EQ(error->code, ag::VPN_EC_NOERROR) << error->text;

    ASSERT_TRUE(this->wait_event(ag::vpn_client::EVENT_CONNECTED));
    ASSERT_NO_FATAL_FAILURE(wait_log(";; ipv4only.arpa.\tIN\tA"));

    ASSERT_TRUE(this->run_sync_on_ev_loop([this]() {
        this->vpn->disconnect();
    }));

    ASSERT_FALSE(this->wait_event(ag::vpn_client::EVENT_DNS_UPSTREAM_UNAVAILABLE, 3 * DNS_TIMEOUT / 2));
}
