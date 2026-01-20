#include "vpn/internal/icmp_manager.h"

#include <atomic>
#include <chrono>
#include <vector>

#define log_req(mngr_, msg_, lvl_, fmt_, ...)                                                                          \
    lvl_##log((mngr_)->m_log, "[{}] [{}/{}/{}] " fmt_, (mngr_)->m_id, (msg_).peer, (int) (msg_).id,                    \
            (int) (msg_).seqno, ##__VA_ARGS__)
#define log_reply(mngr_, msg_, lvl_, fmt_, ...)                                                                        \
    lvl_##log((mngr_)->m_log, "[{}] [{}/{}/{}] " fmt_, (mngr_)->m_id, (msg_).peer, (int) (msg_).id,                    \
            (int) (msg_).seqno, ##__VA_ARGS__)

using namespace std::chrono;

namespace ag {

struct RequestAttempt {
    uint16_t seqno;
    steady_clock::time_point timeout_ts;
};

struct IcmpManager::RequestInfo {
    SocketAddress original_peer = {};
    std::vector<RequestAttempt> tries;
};

static constexpr seconds DEFAULT_PING_REQUEST_TIMEOUT = seconds(3);

static std::atomic_int g_next_id = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

IcmpRequestKey IcmpRequestKey::make(const IcmpEchoRequest &request) {
    return {request.id};
}

IcmpRequestKey IcmpRequestKey::make(const IcmpEchoReply &reply) {
    return {reply.id};
}

bool IcmpRequestKey::operator<(const IcmpRequestKey &other) const {
    return this->id < other.id;
}

IcmpEchoRequestKey IcmpEchoRequestKey::make(const IcmpEchoRequest &request) {
    return {{request.id}, request.seqno};
}

IcmpEchoRequestKey IcmpEchoRequestKey::make(const IcmpEchoReply &reply) {
    return {{reply.id}, reply.seqno};
}

bool IcmpEchoRequestKey::operator<(const IcmpEchoRequestKey &other) const {
    return this->id < other.id || this->seqno < other.seqno;
}

IcmpManager::IcmpManager()
        : m_id(g_next_id.fetch_add(1, std::memory_order_relaxed)) {
}

IcmpManager::~IcmpManager() = default;

bool IcmpManager::init(Parameters p, IcmpManagerHandler h) {
    m_parameters = p;
    m_parameters.request_timeout = m_parameters.request_timeout.value_or(DEFAULT_PING_REQUEST_TIMEOUT);
    m_handler = h;
    return true;
}

void IcmpManager::deinit() {
    m_timer.reset();
    m_requests.clear();
}

IcmpManagerMessageStatus IcmpManager::register_request(const IcmpEchoRequest &request) {
    log_req(this, request, dbg, "{}", request);

    RequestInfoPtr &info = m_requests[IcmpRequestKey::make(request)];
    if (info == nullptr) {
        info = std::make_unique<RequestInfo>();
        info->original_peer = request.peer;
    }

    bool is_already_on_wire =
            std::any_of(info->tries.begin(), info->tries.end(), [seqno = request.seqno](const RequestAttempt &i) {
                return i.seqno == seqno;
            });
    if (is_already_on_wire) {
        log_req(this, request, dbg, "Such request is already in progress");
        return IM_MSGS_DROP;
    }

    // request_timeout is guaranteed to have a value
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    info->tries.emplace_back(RequestAttempt{
            request.seqno,
            steady_clock::time_point(steady_clock::now() + m_parameters.request_timeout.value()),
    });

    if (m_timer == nullptr) {
        m_timer.reset(event_new(vpn_event_loop_get_base(m_parameters.ev_loop), -1, EV_PERSIST, timer_callback, this));
        const timeval tv = ms_to_timeval(uint32_t(m_parameters.request_timeout.value().count() / 10));
        event_add(m_timer.get(), &tv);
    }
    // NOLINTEND(bugprone-unchecked-optional-access)

    return IM_MSGS_PASS;
}

IcmpManagerMessageStatus IcmpManager::register_reply(IcmpEchoReply &reply) {
    log_reply(this, reply, dbg, "{}", reply);

    auto request_it = m_requests.find(IcmpRequestKey::make(reply));
    if (request_it == m_requests.end()) {
        log_reply(this, reply, dbg, "There's no request with such ID");
        return IM_MSGS_DROP;
    }

    RequestInfoPtr &info = request_it->second;
    if (info == nullptr) {
        m_requests.erase(request_it);
        log_reply(this, reply, dbg, "There's no request with such ID");
        assert(0);
        return IM_MSGS_DROP;
    }

    auto try_it = info->tries.end();
    if (!(reply.peer.is_ipv4() && reply.type != ICMP_MT_ECHO_REPLY)
            && !(reply.peer.is_ipv6() && reply.type != ICMPV6_MT_ECHO_REPLY)) {
        try_it = std::find_if(info->tries.begin(), info->tries.end(), [seqno = reply.seqno](const RequestAttempt &i) {
            return i.seqno == seqno;
        });
    } else if (!info->tries.empty()) {
        try_it = info->tries.begin();
        reply.seqno = try_it->seqno;
    }

    if (try_it == info->tries.end()) {
        log_reply(this, reply, dbg, "There's no request with such sequence number");
        return IM_MSGS_DROP;
    }

    assert(reply.seqno == try_it->seqno);
    info->tries.erase(try_it);
    if (info->tries.empty()) {
        m_requests.erase(request_it);
    }

    return IM_MSGS_PASS;
}

static IcmpEchoReply make_reply_on_timeout(const IcmpRequestKey &key, const SocketAddress &peer, uint16_t seqno) {
    return {
            .peer = peer,
            .id = key.id,
            .seqno = seqno,
            .type = ICMP_MT_DROP,
            .code = 0,
    };
}

void IcmpManager::timer_callback(evutil_socket_t, short, void *arg) {
    auto *self = (IcmpManager *) arg;

    steady_clock::time_point now = steady_clock::now();
    for (auto i = self->m_requests.begin(); i != self->m_requests.end();) {
        const IcmpRequestKey &key = i->first;
        RequestInfo &info = *i->second;
        for (auto j = info.tries.begin(); j != info.tries.end();) {
            const RequestAttempt &req_try = *j;
            if (now < req_try.timeout_ts) {
                ++j;
                continue;
            }

            IcmpEchoReply reply = make_reply_on_timeout(key, info.original_peer, req_try.seqno);
            log_reply(self, reply, dbg, "Request has timed out");
            self->m_handler.on_reply_ready(self->m_handler.arg, reply);
            j = info.tries.erase(j);
        }

        if (info.tries.empty()) {
            i = self->m_requests.erase(i);
        } else {
            ++i;
        }
    }
}

} // namespace ag
