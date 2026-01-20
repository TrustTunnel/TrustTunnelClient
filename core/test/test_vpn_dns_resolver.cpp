#include <thread>

#include <gtest/gtest.h>

#include "vpn/internal/vpn_client.h"
#include "vpn/internal/vpn_dns_resolver.h"

#define EXAMPLE_ORG_A_REPLY_NO_ID                                                                                      \
    0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,  \
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x1c,      \
            0x13, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22, 0x00, 0x00, 0x29, 0xff, 0xd6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

using namespace ag;

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
class VpnDnsResolverTest : public testing::Test {
public:
    VpnDnsResolverTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    std::unique_ptr<ClientListener> resolver;
    std::vector<uint64_t> raised_connection_requests;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> raised_reads;
    std::optional<std::pair<VpnDnsResolveId, VpnDnsResolverResult>> raised_result;
    ag::DeclPtr<ag::VpnNetworkManager, &ag::vpn_network_manager_destroy> network_manager{ag::vpn_network_manager_get()};
    ag::vpn_client::Parameters parameters = {
            .ev_loop = this->ev_loop.get(),
            .network_manager = this->network_manager.get(),
    };
    std::unique_ptr<ag::VpnClient> vpn = std::make_unique<ag::VpnClient>(this->parameters);

    void SetUp() override {
        this->resolver = std::make_unique<VpnDnsResolver>();
        ASSERT_EQ(ClientListener::InitResult::SUCCESS, this->resolver->init(this->vpn.get(), {resolver_handler, this}));
    }

    static void resolver_handler(void *arg, ClientEvent what, void *data) {
        auto *self = (VpnDnsResolverTest *) arg;

        switch (what) {
        case CLIENT_EVENT_CONNECT_REQUEST: {
            const auto *event = (ClientConnectRequest *) data;
            self->raised_connection_requests.push_back(event->id);
            break;
        }
        case CLIENT_EVENT_READ: {
            auto *event = (ClientRead *) data;
            self->raised_reads.emplace_back(event->id, std::vector<uint8_t>{event->data, event->data + event->length});
            event->result = (int) event->length;
            break;
        }
        default:
            break;
        }
    }

    static void result_handler(void *arg, VpnDnsResolveId id, VpnDnsResolverResult result) {
        auto *self = (VpnDnsResolverTest *) arg;
        self->raised_result.emplace(id, std::move(result));
    }

    void run_event_loop_once() { // NOLINT(readability-make-member-function-const)
        vpn_event_loop_exit(this->ev_loop.get(), Millis{0});
        vpn_event_loop_run(this->ev_loop.get());
    }
};

TEST_F(VpnDnsResolverTest, ResolveV4Only) {
    ((VpnDnsResolver *) this->resolver.get())
            ->resolve(VDRQ_BACKGROUND, "example.org", 1 << dns_utils::RT_A, {result_handler, this});
    ASSERT_EQ(this->raised_connection_requests.size(), 0);

    this->run_event_loop_once();

    ASSERT_EQ(this->raised_connection_requests.size(), 1);
    uint64_t connection_id = this->raised_connection_requests[0];
    this->resolver->complete_connect_request(connection_id, CCR_PASS);
    this->run_event_loop_once();
    ASSERT_EQ(this->raised_reads.size(), 1);

    const uint8_t REPLY[] = {
            this->raised_reads[0].second[0], this->raised_reads[0].second[1], EXAMPLE_ORG_A_REPLY_NO_ID};
    this->raised_reads.clear();

    ASSERT_EQ(this->resolver->send(connection_id, REPLY, std::size(REPLY)), std::size(REPLY));
    this->run_event_loop_once();
    ASSERT_TRUE(this->raised_result.has_value());

    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    const auto *result = std::get_if<VpnDnsResolverSuccess>(&this->raised_result->second);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->addresses.size(), 1);
    ASSERT_TRUE(result->addresses[0].is_ipv4());
}

TEST_F(VpnDnsResolverTest, ResultV6) {
    ((VpnDnsResolver *) this->resolver.get())
            ->resolve(VDRQ_BACKGROUND, "example.org", 1 << dns_utils::RT_A | 1 << dns_utils::RT_AAAA,
                    {result_handler, this});
    ASSERT_EQ(this->raised_connection_requests.size(), 0);

    this->run_event_loop_once();

    ASSERT_EQ(this->raised_connection_requests.size(), 1);
    uint64_t connection_id = this->raised_connection_requests[0];
    this->resolver->complete_connect_request(connection_id, CCR_PASS);
    this->run_event_loop_once();
    ASSERT_EQ(this->raised_reads.size(), 2);

    const uint8_t A_REPLY[] = {
            this->raised_reads[0].second[0], this->raised_reads[0].second[1], EXAMPLE_ORG_A_REPLY_NO_ID};
    const uint8_t AAAA_REPLY[] = {this->raised_reads[1].second[0], this->raised_reads[1].second[1], 0x81, 0x80, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f, 0x72,
            0x67, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x00, 0xdf, 0x00, 0x10,
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46, 0x00, 0x00,
            0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    this->raised_reads.clear();

    ASSERT_EQ(this->resolver->send(connection_id, A_REPLY, std::size(A_REPLY)), std::size(A_REPLY));
    ASSERT_EQ(this->resolver->send(connection_id, AAAA_REPLY, std::size(AAAA_REPLY)), std::size(AAAA_REPLY));
    this->run_event_loop_once();
    ASSERT_TRUE(this->raised_result.has_value());

    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    const auto *result = std::get_if<VpnDnsResolverSuccess>(&this->raised_result->second);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->addresses.size(), 2);
    ASSERT_TRUE(result->addresses[0].is_ipv4());
    ASSERT_TRUE(result->addresses[1].is_ipv6());
}

TEST_F(VpnDnsResolverTest, Cancel) {
    std::optional<VpnDnsResolveId> id =
            ((VpnDnsResolver *) this->resolver.get())
                    ->resolve(VDRQ_BACKGROUND, "example.org", 1 << dns_utils::RT_A, {result_handler, this});
    ASSERT_TRUE(id.has_value());
    ASSERT_EQ(this->raised_connection_requests.size(), 0);

    this->run_event_loop_once();

    ASSERT_EQ(this->raised_connection_requests.size(), 1);
    uint64_t connection_id = this->raised_connection_requests[0];
    this->resolver->complete_connect_request(connection_id, CCR_PASS);
    this->run_event_loop_once();
    ASSERT_EQ(this->raised_reads.size(), 1);

    const uint8_t REPLY[] = {
            this->raised_reads[0].second[0], this->raised_reads[0].second[1], EXAMPLE_ORG_A_REPLY_NO_ID};
    this->raised_reads.clear();

    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    ((VpnDnsResolver *) this->resolver.get())->cancel(id.value());

    ASSERT_EQ(this->resolver->send(connection_id, REPLY, std::size(REPLY)), std::size(REPLY));
    this->run_event_loop_once();
    ASSERT_FALSE(this->raised_result.has_value());
}

TEST_F(VpnDnsResolverTest, BackgroundsDontBlockForegrounds) {
    ((VpnDnsResolver *) this->resolver.get())->resolve(VDRQ_BACKGROUND, "example.org");
    this->run_event_loop_once();
    this->resolver->complete_connect_request(this->raised_connection_requests[0], CCR_PASS);
    this->run_event_loop_once();
    ASSERT_EQ(this->raised_reads.size(), 2);

    auto initiate_resolve = [this](VpnDnsResolverQueue queue) {
        ((VpnDnsResolver *) this->resolver.get())->resolve(queue, "example.org");
        this->run_event_loop_once();
    };

    for (size_t i = this->raised_reads.size() / 2 + 1; i < VpnDnsResolver::MAX_PARALLEL_BACKGROUND_RESOLVES + 5; ++i) {
        ASSERT_NO_FATAL_FAILURE(initiate_resolve(VDRQ_BACKGROUND));
        ASSERT_EQ(this->raised_reads.size(), std::min(2 * i, VpnDnsResolver::MAX_PARALLEL_BACKGROUND_RESOLVES));
    }

    for (size_t i = 1; i < 10; ++i) {
        ASSERT_NO_FATAL_FAILURE(initiate_resolve(VDRQ_FOREGROUND));
        ASSERT_EQ(this->raised_reads.size(), VpnDnsResolver::MAX_PARALLEL_BACKGROUND_RESOLVES + 2 * i);
    }
}

TEST_F(VpnDnsResolverTest, ForegroundsBlockBackgrounds) {
    ((VpnDnsResolver *) this->resolver.get())->resolve(VDRQ_FOREGROUND, "example.org");
    this->run_event_loop_once();
    this->resolver->complete_connect_request(this->raised_connection_requests[0], CCR_PASS);
    this->run_event_loop_once();
    ASSERT_EQ(this->raised_reads.size(), 2);

    auto initiate_resolve = [this](VpnDnsResolverQueue queue) {
        ((VpnDnsResolver *) this->resolver.get())->resolve(queue, "example.org");
        this->run_event_loop_once();
    };

    for (size_t i = this->raised_reads.size() / 2 + 1; i < VpnDnsResolver::MAX_PARALLEL_BACKGROUND_RESOLVES + 5; ++i) {
        ASSERT_NO_FATAL_FAILURE(initiate_resolve(VDRQ_FOREGROUND));
        ASSERT_EQ(this->raised_reads.size(), 2 * i);
    }

    size_t current_queries_number = this->raised_reads.size();
    for (size_t i = 1; i < 10; ++i) {
        ASSERT_NO_FATAL_FAILURE(initiate_resolve(VDRQ_BACKGROUND));
        ASSERT_EQ(this->raised_reads.size(), current_queries_number);
    }
}

TEST_F(VpnDnsResolverTest, QueryTimeout) {
    // This should be bigger than 1ms (to prevent executing on current loop cycle), but lesser than 1000ms
    VpnDnsResolver::set_query_timeout(Millis{300});

    ((VpnDnsResolver *) this->resolver.get())
            ->resolve(VDRQ_BACKGROUND, "example.org", VpnDnsResolver::RecordTypeSet{}.set(), {result_handler, this});
    ASSERT_EQ(this->raised_connection_requests.size(), 0);

    this->run_event_loop_once();

    ASSERT_EQ(this->raised_connection_requests.size(), 1);
    uint64_t connection_id = this->raised_connection_requests[0];
    this->resolver->complete_connect_request(connection_id, CCR_PASS);
    this->run_event_loop_once();
    ASSERT_EQ(this->raised_reads.size(), 2);

    const uint8_t A_REPLY[] = {
            this->raised_reads[0].second[0], this->raised_reads[0].second[1], EXAMPLE_ORG_A_REPLY_NO_ID};
    this->raised_reads.clear();

    ASSERT_EQ(this->resolver->send(connection_id, A_REPLY, std::size(A_REPLY)), std::size(A_REPLY));
    this->run_event_loop_once();

    std::this_thread::sleep_for(Secs{1});

    this->run_event_loop_once();
    ASSERT_TRUE(this->raised_result.has_value());
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    const auto *result = std::get_if<VpnDnsResolverSuccess>(&this->raised_result->second);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->addresses.size(), 1);
    ASSERT_TRUE(result->addresses[0].is_ipv4());
}

TEST_F(VpnDnsResolverTest, ConnectionTimeout) {
    this->vpn->upstream_config.timeout = Millis{1};

    ((VpnDnsResolver *) this->resolver.get())
            ->resolve(VDRQ_BACKGROUND, "example.org", 1 << dns_utils::RT_A, {result_handler, this});
    ASSERT_EQ(this->raised_connection_requests.size(), 0);

    this->run_event_loop_once();

    ASSERT_EQ(this->raised_connection_requests.size(), 1);
    uint64_t connection_id = this->raised_connection_requests[0];
    this->resolver->complete_connect_request(connection_id, CCR_PASS);
    this->run_event_loop_once();
    ASSERT_EQ(this->raised_reads.size(), 1);
    this->raised_reads.clear();

    std::this_thread::sleep_for(Secs{1});

    this->run_event_loop_once();
    ASSERT_TRUE(this->raised_result.has_value());
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    ASSERT_TRUE(std::holds_alternative<VpnDnsResolverFailure>(this->raised_result->second));
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
