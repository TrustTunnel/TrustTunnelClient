#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <optional>

#include <event2/event.h>

#include "common/logger.h"
#include "vpn/event_loop.h"
#include "vpn/internal/utils.h"
#include "vpn/utils.h"

namespace ag {

struct IcmpRequestKey {
    uint16_t id = 0;

    static IcmpRequestKey make(const IcmpEchoRequest &request);
    static IcmpRequestKey make(const IcmpEchoReply &reply);
    bool operator<(const IcmpRequestKey &other) const;
};

struct IcmpEchoRequestKey : public IcmpRequestKey {
    uint16_t seqno = 0;

    static IcmpEchoRequestKey make(const IcmpEchoRequest &request);
    static IcmpEchoRequestKey make(const IcmpEchoReply &reply);
    bool operator<(const IcmpEchoRequestKey &other) const;
};

enum IcmpManagerMessageStatus {
    /** A message should be passed further to the destination */
    IM_MSGS_PASS,
    /** A message should be dropped */
    IM_MSGS_DROP,
};

struct IcmpManagerHandler {
    /** Raised when an ICMP reply should be sent to the client */
    void (*on_reply_ready)(void *arg, const IcmpEchoReply &reply);
    /** User context */
    void *arg;
};

class IcmpManager {
public:
    struct Parameters {
        /** Event loop for operation */
        VpnEventLoop *ev_loop;
        /** ICMP request timeout */
        std::optional<std::chrono::milliseconds> request_timeout;
    };

    IcmpManager();
    ~IcmpManager();
    IcmpManager(IcmpManager &&) = default;
    IcmpManager &operator=(IcmpManager &&) = default;

    IcmpManager(const IcmpManager &) = delete;
    IcmpManager &operator=(const IcmpManager &) = delete;

    /**
     * Initialize the ICMP manager
     * @return true if successful
     */
    bool init(Parameters parameters, IcmpManagerHandler handler);

    /**
     * Deinitialize the ICMP manager
     */
    void deinit();

    /**
     * Register a request received from client
     * @return see `IcmpManagerMessageStatus`
     */
    IcmpManagerMessageStatus register_request(const IcmpEchoRequest &request);

    /**
     * Register a reply received from remote host
     * @param reply  the reply (may be modified)
     * @return see `IcmpManagerMessageStatus`
     */
    IcmpManagerMessageStatus register_reply(IcmpEchoReply &reply);

private:
    struct RequestInfo;
    using RequestInfoPtr = std::unique_ptr<RequestInfo>;

    std::map<IcmpRequestKey, RequestInfoPtr> m_requests;
    Parameters m_parameters = {};
    IcmpManagerHandler m_handler = {};
    DeclPtr<event, &event_free> m_timer;

    ag::Logger m_log{"ICMP"};
    int m_id;

    static void timer_callback(evutil_socket_t, short, void *arg);
};

} // namespace ag
