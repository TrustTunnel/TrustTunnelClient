#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <vector>

#include "vpn/internal/vpn_client.h"

namespace test_mock {

enum ClientMethodId {
    CMID_CONNECT,
    CMID_DISCONNECT,
    CMID_DO_HEALTH_CHECK,
    CMID_COMPLETE_CONNECT_REQUEST,
    CMID_REJECT_CONNECT_REQUEST,
    CMID_RESET_CONNECTION,
};

struct MockedVpnClient {
    ag::VpnError error = {};
    std::optional<ClientMethodId> last_client_method_called;
    std::mutex guard;
    std::condition_variable call_barrier;

    struct completed_connect_request_t {
        uint64_t id;
        std::optional<ag::VpnConnectAction> action;

        completed_connect_request_t(uint64_t id, std::optional<ag::VpnConnectAction> action)
                : id{id}
                , action{action} {
        }
    };

    std::vector<completed_connect_request_t> completed_connect_requests;
    std::vector<uint64_t> rejected_connect_requests;
    std::vector<uint64_t> reset_connections;
    bool is_dropping_non_app_initiated_dns_queries = false;
    /** Called from `VpnClient::finalize_disconnect()`; used to simulate a handler fired on the stopping thread. */
    std::function<void()> on_finalize_disconnect;

    bool wait_called(ClientMethodId method, std::optional<std::chrono::milliseconds> timeout = std::nullopt) {
        std::unique_lock l(this->guard);
        bool status = this->call_barrier.wait_for(l, timeout.value_or(std::chrono::seconds(10)), [this, method]() {
            return this->last_client_method_called == method;
        });
        this->last_client_method_called.reset();
        return status;
    }

    void notify_called(ClientMethodId method) {
        std::unique_lock l(this->guard);
        this->last_client_method_called = method;
        this->call_barrier.notify_all();
    }

    void reset() {
        this->error = {};
        this->last_client_method_called.reset();
        this->completed_connect_requests.clear();
        this->rejected_connect_requests.clear();
        this->reset_connections.clear();
        this->on_finalize_disconnect = nullptr;
    }
};

extern MockedVpnClient g_client;

} // namespace test_mock
