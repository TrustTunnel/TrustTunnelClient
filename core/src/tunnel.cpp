#include "vpn/internal/tunnel.h"

#include <algorithm>
#include <atomic>
#include <bitset>
#include <cassert>
#include <optional>
#include <utility>
#include <vector>

#include <magic_enum/magic_enum.hpp>

#include "common/net_utils.h"
#include "connection_statistics.h"
#include "dns_handler.h"
#include "fake_upstream.h"
#include "net/dns_utils.h"
#include "net/quic_utils.h"
#include "net/utils.h"
#include "socks_listener.h"
#include "vpn/internal/utils.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/utils.h"

#define log_tun(tun_, lvl_, fmt_, ...) lvl_##log((tun_)->log, "[{}] " fmt_, (tun_)->id, ##__VA_ARGS__)
#define log_conn(tun_, conn_, lvl_, fmt_, ...)                                                                         \
    lvl_##log((tun_)->log, "[{}] [L:{}-R:{}] " fmt_, (tun_)->id, (int64_t) (conn_)->client_id,                         \
            (int64_t) (conn_)->server_id, ##__VA_ARGS__)

// TODO: either remove quic blocking code or fix it to correctly tell QUIC libraries that connection is unreachable.
#define BLOCK_OLD_QUIC_CONNS 0

namespace ag {

static std::atomic_int g_next_tunnel_id = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

struct CompleteConnectRequestCtx {
    Tunnel *tunnel = nullptr;
    uint64_t listener_conn_id = NON_ID;
    int err_code = -1;
};

// Func: void(VpnConnection *)
// Call `func` for each value in `table`.
template <typename Func>
void vpn_connections_foreach(const khash_t(connections_by_id) * table, Func &&func) {
    for (auto it = kh_begin(table); it != kh_end(table); ++it) {
        if (!kh_exist(table, it)) {
            continue;
        }
        VpnConnection *conn = kh_value(table, it);
        std::forward<Func>(func)(conn);
    }
}

static VpnConnection *vpn_connection_get_by_id(const khash_t(connections_by_id) * table, uint64_t id) {
    VpnConnection *conn = nullptr;

    khiter_t iter = kh_get(connections_by_id, table, id);
    if (iter != kh_end(table)) {
        conn = kh_value(table, iter);
    }

    return conn;
}

static void vpn_connection_put(khash_t(connections_by_id) * table, uint64_t id, VpnConnection *conn) {
    int r = 0;
    khiter_t iter = kh_put(connections_by_id, table, id, &r);
    assert(r >= 0);
    if (r >= 0) {
        kh_value(table, iter) = conn;
    }
}

static void vpn_connection_remove(khash_t(connections_by_id) * table, uint64_t id) {
    khiter_t iter = kh_get(connections_by_id, table, id);
    if (iter != kh_end(table)) {
        kh_del(connections_by_id, table, iter);
    }
}

static void add_connection(Tunnel *tunnel, VpnConnection *conn) {
    assert(conn->client_id != NON_ID || conn->server_id != NON_ID);

    if (conn->client_id != NON_ID) {
        vpn_connection_put(tunnel->connections.by_client_id, conn->client_id, conn);
    }
    if (conn->server_id != NON_ID) {
        vpn_connection_put(tunnel->connections.by_server_id, conn->server_id, conn);
    }
}

static void cancel_destination_resolve(Tunnel *self, VpnConnection *conn) {
    auto it = std::find_if(
            self->dns_resolve_waiters.begin(), self->dns_resolve_waiters.end(), [id = conn->client_id](const auto &i) {
                return i.second.conn_client_id == id;
            });
    if (it != self->dns_resolve_waiters.end()) {
        self->dns_resolver->cancel(it->first);
        self->dns_resolve_waiters.erase(it);
    }
}

static void destroy_connection(Tunnel *tunnel, uint64_t client_id, uint64_t server_id) {
    assert(client_id != NON_ID || server_id != NON_ID);

    VpnConnection *conn = nullptr;
    if (client_id != NON_ID) {
        conn = vpn_connection_get_by_id(tunnel->connections.by_client_id, client_id);
    }
    if (conn == nullptr && server_id != NON_ID) {
        conn = vpn_connection_get_by_id(tunnel->connections.by_server_id, server_id);
    }

    if (conn != nullptr) {
        if (conn->state == CONNS_WAITING_RESOLVE) {
            cancel_destination_resolve(tunnel, conn);
        }

        vpn_connection_remove(tunnel->connections.by_client_id, conn->client_id);
        vpn_connection_remove(tunnel->connections.by_server_id, conn->server_id);

        if (conn->proto == IPPROTO_UDP && tunnel->udp_close_wait_hostname_cache) {
            std::scoped_lock l(tunnel->udp_close_wait_hostname_cache->mtx);
            tunnel->udp_close_wait_hostname_cache->val.insert(conn->addr, conn->domain_lookuper_result);
        }

        log_conn(tunnel, conn, dbg, "Destroyed (download={}, upload={})", conn->incoming_bytes, conn->outgoing_bytes);

        if (conn->flags.test(CONNF_MONITOR_STATS)) {
            tunnel->statistics_monitor->unregister_conn(conn->client_id, /*do_report*/ true);
        }
        if (!conn->listener.expired() && conn->listener.lock().get() == tunnel->vpn->client_listener.get()) {
            VpnTunnelConnectionClosedEvent event{
                    .id = conn->client_id,
            };
            const vpn_client::Handler &handler = tunnel->vpn->parameters.handler;
            handler.func(handler.arg, vpn_client::EVENT_CONNECTION_CLOSED, &event);
        }

        assert(nullptr == vpn_connection_get_by_id(tunnel->connections.by_client_id, conn->client_id));
        assert(nullptr == vpn_connection_get_by_id(tunnel->connections.by_server_id, conn->server_id));
        delete conn;
    } else {
        log_tun(tunnel, dbg, "Trying to destroy non-existent connection: L:{}-R:{}", client_id, server_id);
        return;
    }

    log_tun(tunnel, dbg, "Remaining connections: client-side={} server-side={}",
            (int) kh_size(tunnel->connections.by_client_id), (int) kh_size(tunnel->connections.by_server_id));
}

static ClientConnectResult server_error_to_connect_result(int err) {
    switch (err) {
    case 0:
        return CCR_PASS;
    case ag::utils::AG_ETIMEDOUT:
        return CCR_DROP;
    case AG_ENETUNREACH:
    case AG_EHOSTUNREACH:
        return CCR_UNREACH;
    default:
        return CCR_REJECT;
    }
}

static void complete_connect_request_task(void *arg, TaskId) {
    auto *ctx = (CompleteConnectRequestCtx *) arg;
    Tunnel *tunnel = ctx->tunnel;

    VpnConnection *conn = vpn_connection_get_by_id(tunnel->connections.by_client_id, ctx->listener_conn_id);
    if (conn == nullptr) {
        log_tun(tunnel, dbg, "Connection not found: L:{}", ctx->listener_conn_id);
        assert(0);
        return;
    }

    conn->complete_connect_request_task.release();

    std::shared_ptr<ClientListener> listener = conn->listener.lock();
    if (listener == nullptr) {
        log_conn(tunnel, conn, dbg, "Listener was deleted");
        destroy_connection(tunnel, ctx->listener_conn_id, NON_ID);
        return;
    }

    switch (conn->state) {
    case CONNS_WAITING_RESOLVE:
    case CONNS_WAITING_RESPONSE:
    case CONNS_WAITING_ACTION: {
        ClientConnectResult result = server_error_to_connect_result(ctx->err_code);
        listener->complete_connect_request(conn->client_id, result);
        if (result != CCR_PASS) {
            // Relookup connection since complete_connect_request may lead to it's close.
            conn = vpn_connection_get_by_id(tunnel->connections.by_client_id, ctx->listener_conn_id);
            if (conn != nullptr) {
                conn->state = CONNS_REJECTED;
            }
        }
        break;
    }
    case CONNS_REJECTED:
    case CONNS_WAITING_ACCEPT:
    case CONNS_CONNECTED:
    case CONNS_CONNECTED_MIGRATING:
    case CONNS_WAITING_RESPONSE_MIGRATING:
        log_conn(tunnel, conn, dbg, "Invalid connection state: {}", magic_enum::enum_name(conn->state));
        listener->close_connection(ctx->listener_conn_id, false, false);
        assert(0);
        break;
    }
}

static void close_client_side_connection(Tunnel *self, VpnConnection *conn, int err_code, bool async) {
    std::shared_ptr<ClientListener> listener = conn->listener.lock();
    if (listener == nullptr) {
        log_conn(self, conn, dbg, "Listener was deleted");
        destroy_connection(self, conn->client_id, conn->server_id);
        return;
    }

    switch (conn->state) {
    case CONNS_WAITING_ACCEPT:
    case CONNS_CONNECTED:
    case CONNS_CONNECTED_MIGRATING:
    case CONNS_REJECTED:
        // will be deleted in connection closed event
        listener->close_connection(conn->client_id, err_code == 0, async);
        break;
    case CONNS_WAITING_RESOLVE:
    case CONNS_WAITING_RESPONSE:
    case CONNS_WAITING_ACTION:
        err_code = (err_code == 0) ? ag::utils::AG_ECONNREFUSED : err_code;
        if (!async) {
            auto result = server_error_to_connect_result(err_code);
            uint64_t conn_client_id = conn->client_id;
            listener->complete_connect_request(conn->client_id, result);
            if (result != CCR_PASS) {
                conn = vpn_connection_get_by_id(self->connections.by_client_id, conn_client_id);
                if (conn != nullptr) {
                    conn->state = CONNS_REJECTED;
                }
            }
            break;
        }

        if (conn->complete_connect_request_task.has_value()) {
            break;
        }

        conn->complete_connect_request_task = event_loop::submit(self->vpn->parameters.ev_loop,
                {
                        new CompleteConnectRequestCtx{self, conn->client_id, err_code},
                        complete_connect_request_task,
                        [](void *arg) {
                            delete (CompleteConnectRequestCtx *) arg;
                        },
                });
        break;
    case CONNS_WAITING_RESPONSE_MIGRATING:
        // do nothing
        break;
    }
}

static void close_client_side(Tunnel *tunnel, ServerUpstream *upstream) {
    if (tunnel->connections.by_client_id == nullptr) {
        return;
    }
    kh_connections_by_id_t *table = tunnel->connections.by_client_id;

    // `close_client_side_connection()` might insert new connections into the table,
    // leading to undefined behaviour if called within the foreach loop
    std::vector<uint64_t> ids;
    ids.reserve(kh_size(table));

    vpn_connections_foreach(table, [&](VpnConnection *conn) {
        if (!conn->upstream.expired() && conn->upstream.lock().get() == upstream) {
            ids.push_back(conn->client_id);
        }
    });

    for (uint64_t id : ids) {
        if (VpnConnection *conn = vpn_connection_get_by_id(table, id)) {
            conn->flags.set(CONNF_SESSION_CLOSED);
            close_client_side_connection(tunnel, conn, -1, false);
        }
    }
}

enum AfterLookuperAction {
    ALUA_DONE,      // lookuper has nothing more to do
    ALUA_PASS,      // lookuper wants to process the next packet, the current one can be sent
    ALUA_DROP,      // lookuper wants to process the next packet, the current one can be dropped
    ALUA_SHUTDOWN,  // lookuper realized that connection should've been routed to another upstream
    ALUA_BLOCK,     // lookuper realized that connection shouldn't be processed
    ALUA_WANT_MORE, // the same as `ALUA_PASS`, but waiting for a packet divided by AntiDpi
};

static std::variant<AfterLookuperAction, DomainLookuperResult> lookup_udp(
        Tunnel *tunnel, VpnConnection *conn, DomainLookuperPacketDirection dir, const uint8_t *data, size_t length) {
    // parse quic header
    auto quic_header = ag::quic_utils::parse_quic_header({data, length});
    if (quic_header.has_value()) {
        if (quic_header->type == ag::quic_utils::ZERO_RTT) {
            return ALUA_DROP;
        }
        if (quic_header->type == ag::quic_utils::INITIAL) {
            // quic traffic
            auto quic_data = ag::quic_utils::prepare_for_domain_lookup({data, length}, quic_header.value());
            if (!quic_data.has_value()) {
                // no data for domain lookup
                return ALUA_DONE;
            }
            return conn->domain_lookuper.proceed(dir, conn->proto, quic_data->data(), quic_data->size());
        }
    }

    if (tunnel->udp_close_wait_hostname_cache) {
        std::scoped_lock l(tunnel->udp_close_wait_hostname_cache->mtx);
        if (auto value = tunnel->udp_close_wait_hostname_cache->val.get(conn->addr); value) {
            log_conn(tunnel, conn, dbg, "Found cached result for pass_through_lookuper");
            return DomainLookuperResult{*value};
        }
    }

#if BLOCK_OLD_QUIC_CONNS
    // get destination port
    const sockaddr *dst = (sockaddr *) std::get_if<sockaddr_storage>(&conn->addr.dst);
    assert(dst != nullptr);
    auto dst_port = sockaddr_get_port(dst);
    // Check if destination is default quic port
    if (dst_port == ag::quic_utils::DEFAULT_QUIC_PORT) {
        // expected to get quic initial, but got wrong data, block it
        return ALUA_BLOCK;
    }
#endif
    // simple udp traffic
    return ALUA_DONE;
}

static AfterLookuperAction pass_through_lookuper(
        Tunnel *tunnel, VpnConnection *conn, DomainLookuperPacketDirection dir, const uint8_t *data, size_t length) {
    DomainLookuper *lookuper = &conn->domain_lookuper;
    DomainLookuperResult r;
    AfterLookuperAction action = ALUA_DONE;
    DomainFilter *filter = &tunnel->vpn->domain_filter;
    if (conn->proto == IPPROTO_UDP) {
        auto result = lookup_udp(tunnel, conn, dir, data, length);
        if (auto *result_action = std::get_if<AfterLookuperAction>(&result)) {
            return *result_action;
        }
        r = std::get<DomainLookuperResult>(result);
    } else {
        // tcp traffic
        r = lookuper->proceed(dir, conn->proto, data, length);
    }
    conn->domain_lookuper_result = r;

    switch (r.status) {
    case DLUS_NOTFOUND:
        log_conn(tunnel, conn, dbg, "Gave up to find domain name");
        lookuper->reset();
        break;
    case DLUS_FOUND: {
        log_conn(tunnel, conn, dbg, "Found domain in {} data: {}", (dir == DLUPD_OUTGOING) ? "outgoing" : "incoming",
                r.domain);
        if (DFMS_EXCLUSION == filter->match_domain(r.domain)) {
            action = ALUA_SHUTDOWN;
        }
        filter->add_resolved_tag(conn->make_tag(), std::move(r.domain));
        lookuper->reset();
        break;
    }
    case DLUS_PASS:
        action = ALUA_PASS;
        break;
    case DLUS_WANT_MORE:
        action = ALUA_WANT_MORE;
        break;
    }

    return action;
}

static bool is_domain_scannable_port(uint16_t port) {
    static constexpr uint16_t SCANNABLE_PORTS[] = {443, 80, 8080, 8008};
    return std::any_of(std::begin(SCANNABLE_PORTS), std::end(SCANNABLE_PORTS), [port](uint16_t i) {
        return port == i;
    });
}

static void dns_resolver_handler(void *arg, ClientEvent what, void *data) {
    auto *self = (Tunnel *) arg;
    self->listener_handler(self->dns_resolver, what, data);
}

static bool send_buffered_data(const Tunnel *self, uint64_t conn_client_id) {
    VpnConnection *conn = vpn_connection_get_by_id(self->connections.by_client_id, conn_client_id);
    if (conn == nullptr) {
        log_tun(self, dbg, "Connection not found: [L:{}]", conn_client_id);
        return false;
    }

    std::shared_ptr<ServerUpstream> upstream = conn->upstream.lock();
    if (upstream == nullptr) {
        log_conn(self, conn, dbg, "Upstream was deleted");
        return false;
    }

    std::shared_ptr<ClientListener> listener = conn->listener.lock();
    if (listener == nullptr) {
        log_conn(self, conn, dbg, "Listener was deleted");
        return false;
    }

    conn->send_buffered_task.release();
    for (std::vector<uint8_t> &packet : std::exchange(conn->buffered_packets, {})) {
        log_conn(self, conn, trace, "Sending {} bytes from buffered packets", packet.size());
        ssize_t r = upstream->send(conn->server_id, packet.data(), packet.size());
        if (r >= 0 && size_t(r) == packet.size()) {
            conn->outgoing_bytes += r;
            if (conn->flags.test(CONNF_MONITOR_STATS)) {
                self->statistics_monitor->update_upload(conn_client_id, r);
            }
            continue;
        }

        if (r < 0) {
            log_conn(self, conn, dbg, "Failed to send data: error={}", r);
        } else {
            log_conn(self, conn, dbg, "Sent partially: {} bytes out of {}", r, packet.size());
        }

        listener->close_connection(conn_client_id, false, false);
        return false;
    }

    size_t server_can_send = upstream->available_to_send(conn->server_id);
    log_conn(self, conn, trace, "Server side can send {} bytes", server_can_send);
    listener->turn_read(conn->client_id, server_can_send > 0);
    upstream->update_flow_control(conn->server_id, listener->flow_control_info(conn_client_id));
    return true;
}

static VpnAddress tunnel_to_vpn_address(const TunnelAddress *tunnel);
static VpnFinalConnectionAction get_final_action(VpnMode mode, VpnConnectAction action) {
    if (action == VPN_CA_DEFAULT) {
        switch (mode) {
        case VPN_MODE_GENERAL:
            return VpnFinalConnectionAction::VPN_FCA_TUNNEL;
        case VPN_MODE_SELECTIVE:
            return VpnFinalConnectionAction::VPN_FCA_BYPASS;
        }
    }
    if (action == VPN_CA_FORCE_BYPASS) {
        return VpnFinalConnectionAction::VPN_FCA_BYPASS;
    }
    if (action == VPN_CA_FORCE_REDIRECT) {
        return VpnFinalConnectionAction::VPN_FCA_TUNNEL;
    }
    return VpnFinalConnectionAction::VPN_FCA_REJECT;
}

static void report_connection_info(const Tunnel *self, VpnConnection *conn, const char *domain) {
    // Don't report connection info for loopback, DNS, or already reported connections. Also don't report if we are
    // looking up the domain.
    if (conn->flags.test(CONNF_PLAIN_DNS_CONNECTION) || conn->flags.test(CONNF_LOOKINGUP_DOMAIN)
            || conn->flags.test(CONNF_CONN_INFO_SENT)) {
        return;
    }

    if (const sockaddr *dst = (sockaddr *) std::get_if<sockaddr_storage>(&conn->addr.dst);
            dst && sockaddr_is_loopback(dst)) {
        return;
    }

    conn->flags.set(CONNF_CONN_INFO_SENT);
    VpnConnectionInfoEvent info;
    info.src = &conn->addr.src;
    if (const sockaddr_storage *dst =std::get_if<sockaddr_storage>(&conn->addr.dst)) {
        info.dst = dst;
        info.domain = domain;
    } else {
        info.dst = nullptr;
        info.domain = std::get<NamePort>(conn->addr.dst).name.c_str();
    }
    info.proto = conn->proto;
    info.action = get_final_action(self->vpn->domain_filter.get_mode(), conn->action.value_or(VPN_CA_DEFAULT));

    if (info.domain && info.domain[0] == '\0') {
        info.domain = nullptr;
    }

    self->vpn->parameters.handler.func(self->vpn->parameters.handler.arg, vpn_client::EVENT_CONNECTION_INFO, &info);
}

static std::optional<DnsHandlerParameters> make_dns_handler_parameters(Tunnel *self) {
    DnsHandlerParameters parameters{.cert_verify_handler = self->vpn->parameters.cert_verify_handler};
    if (self->vpn->listener_config.dns_upstreams.size) {
        if (!self->vpn->dns_proxy_listener) {
            log_tun(self, warn, "There are user-provided DNS upstreams, but the DNS proxy listener is not initialized");
            return std::nullopt;
        }
        for (size_t i = 0; i < self->vpn->listener_config.dns_upstreams.size; ++i) {
            parameters.dns_upstreams.emplace_back(
                    DnsProxyAccessor::Upstream{.address = self->vpn->listener_config.dns_upstreams.data[i]});
        }
        parameters.dns_proxy_listener_address =
                ((SocksListener *) self->vpn->dns_proxy_listener.get())->get_listen_address();
    }
    return parameters;
}

void Tunnel::upstream_handler(const std::shared_ptr<ServerUpstream> &upstream, ServerEvent what, void *data) {
    switch (what) {
    case SERVER_EVENT_SESSION_OPENED:
        if (upstream.get() == this->vpn->endpoint_upstream.get()) {
            assert(!this->endpoint_upstream_connected);
            this->endpoint_upstream_connected = true;
        }
        break;
    case SERVER_EVENT_HEALTH_CHECK_RESULT:
        // do nothing
        break;
    case SERVER_EVENT_SESSION_CLOSED:
        close_client_side(this, upstream.get());
        break;
    case SERVER_EVENT_CONNECTION_OPENED: {
        uint64_t id = *(uint64_t *) data;

        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_server_id, id);
        if (conn == nullptr) {
            log_tun(this, warn, "Got server connect result for inexistent or already closed connection: {}", id);
            upstream->close_connection(id, false, true);
            assert(0);
            break;
        }

        if (upstream.get() != conn->upstream.lock().get()) {
            log_conn(this, conn, warn, "Upstream mismatch");
            upstream->close_connection(id, false, true);
            assert(0);
            break;
        }

        std::shared_ptr<ClientListener> listener = conn->listener.lock();
        if (listener == nullptr) {
            log_conn(this, conn, dbg, "Listener was deleted");
            upstream->close_connection(id, false, true);
            assert(0);
            break;
        }

        switch (conn->state) {
        case CONNS_WAITING_RESPONSE: {
            log_conn(this, conn, dbg, "Successfully made tunnel");
            report_connection_info(this, conn, conn->domain_lookuper_result.domain.c_str());
            conn->state = CONNS_WAITING_ACCEPT;
            listener->complete_connect_request(conn->client_id, CCR_PASS);
            break;
        }
        case CONNS_WAITING_RESPONSE_MIGRATING: {
            VpnConnection *src_conn =
                    vpn_connection_get_by_id(this->connections.by_client_id, conn->migrating_client_id);
            if (src_conn == nullptr) {
                log_conn(this, conn, dbg, "Migrating connection closed while had being connecting to another upstream");
                upstream->close_connection(id, false, true);
                break;
            }

            std::swap(conn->client_id, src_conn->client_id);
            conn->state = CONNS_CONNECTED;
            conn->migrating_client_id = NON_ID;
            add_connection(this, conn);
            if (conn->proto == IPPROTO_UDP) {
                std::swap(((UdpVpnConnection *) conn)->buffered_packets,
                        ((UdpVpnConnection *) src_conn)->buffered_packets);
            }

            if (std::shared_ptr<ServerUpstream> src_conn_upstream = src_conn->upstream.lock();
                    src_conn_upstream != nullptr) {
                src_conn_upstream->close_connection(src_conn->server_id, false, false);
            }

            log_conn(this, conn, dbg, "Upstream has been switched successfully");
            if (!conn->buffered_packets.empty()) {
                struct Ctx {
                    Tunnel *tunnel;
                    uint64_t conn_client_id;
                };
                conn->send_buffered_task = event_loop::submit(this->vpn->parameters.ev_loop,
                        {
                                new Ctx{this, conn->client_id},
                                [](void *arg, TaskId) {
                                    auto *ctx = (Ctx *) arg;
                                    send_buffered_data(ctx->tunnel, ctx->conn_client_id);
                                },
                                [](void *arg) {
                                    delete (Ctx *) arg;
                                },
                        });
                break;
            }

            listener->turn_read(conn->client_id, true);
            upstream->update_flow_control(conn->server_id, listener->flow_control_info(conn->client_id));
            break;
        }
        default:
            log_conn(this, conn, err, "Connection has invalid state: {} (event={})", magic_enum::enum_name(conn->state),
                    magic_enum::enum_name(what));
            assert(0);
            upstream->close_connection(id, false, true);
            break;
        }
        break;
    }
    case SERVER_EVENT_CONNECTION_CLOSED: {
        uint64_t id = *(uint64_t *) data;

        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_server_id, id);
        if (conn == nullptr) {
            log_tun(this, dbg, "Got close event for nonexistent or already closed connection: R:{}", id);
            destroy_connection(this, NON_ID, id);
            break;
        }

        log_conn(this, conn, dbg, "Connection closed");
        if (std::shared_ptr<ClientListener> listener;
                nullptr != vpn_connection_get_by_id(this->connections.by_client_id, conn->client_id)
                && nullptr != (listener = conn->listener.lock())) {
            vpn_connection_remove(this->connections.by_server_id, conn->server_id);
            listener->turn_read(conn->client_id, false);
            close_client_side_connection(this, conn, 0, false);
        } else {
            destroy_connection(this, conn->client_id, conn->server_id);
        }
        break;
    }
    case SERVER_EVENT_READ: {
        auto *event = (ServerReadEvent *) data;

        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_server_id, event->id);
        if (conn == nullptr) {
            log_tun(this, dbg, "Got data from server for inexistent or already closed connection: {}", event->id);
            event->result = -1;
            assert(0);
            break;
        }

        if (upstream.get() != conn->upstream.lock().get()) {
            log_conn(this, conn, warn, "Upstream mismatch");
            event->result = -1;
            assert(0);
            break;
        }

        std::shared_ptr<ClientListener> listener = conn->listener.lock();
        if (listener == nullptr) {
            log_conn(this, conn, dbg, "Listener was deleted");
            event->result = -1;
            assert(0);
            break;
        }

        log_conn(this, conn, trace, "Received {} bytes from server", event->length);

        if (conn->flags.test(CONNF_LOOKINGUP_DOMAIN)) {
            AfterLookuperAction alua = pass_through_lookuper(this, conn, DLUPD_INCOMING, event->data, event->length);
            log_conn(this, conn, dbg, "alua={}", magic_enum::enum_name(alua));
            switch (alua) {
            case ALUA_DONE:
                conn->flags.reset(CONNF_LOOKINGUP_DOMAIN);
                break;
            case ALUA_PASS:
            case ALUA_WANT_MORE:
            case ALUA_DROP:
                break;
            case ALUA_SHUTDOWN:
                log_conn(this, conn, dbg, "Server: Connection had been routed {}, closing it to re-route",
                        (upstream.get() == this->vpn->endpoint_upstream.get())         ? "through VPN endpoint"
                                : (upstream.get() == this->vpn->bypass_upstream.get()) ? "directly to target host"
                                : (upstream.get() == this->fake_upstream.get())        ? "through fake endpoint"
                                                                                       : "through unknown endpoint");
                close_client_side_connection(this, conn, 0, false);
                return;
            case ALUA_BLOCK:
                log_conn(this, conn, dbg, "Dropped QUIC connection");
                upstream->update_flow_control(event->id, {});
                close_client_side_connection(this, conn, -1, /* async */ false);
                return;
            }
        }

        event->result = (int) listener->send(conn->client_id, event->data, event->length);
        if (event->result == 0) {
            upstream->update_flow_control(conn->server_id, {});
        } else if (event->result > 0) {
            conn->incoming_bytes += event->result;
            if (conn->flags.test(CONNF_MONITOR_STATS)) {
                this->statistics_monitor->update_download(conn->client_id, event->result);
            }
            TcpFlowCtrlInfo info = listener->flow_control_info(conn->client_id);
            log_conn(this, conn, trace, "Client side can send {} bytes", info.send_buffer_size);
            upstream->update_flow_control(conn->server_id, info);
        } else {
            log_conn(this, conn, dbg, "Failed to send data from server");
            // connection will be closed inside upstream
        }
        break;
    }
    case SERVER_EVENT_DATA_SENT: {
        const ServerDataSentEvent *event = (ServerDataSentEvent *) data;

        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_server_id, event->id);
        if (conn == nullptr) {
            break;
        }

        if (upstream.get() != conn->upstream.lock().get()) {
            log_conn(this, conn, warn, "Upstream mismatch");
            upstream->close_connection(id, false, true);
            assert(0);
            break;
        }

        std::shared_ptr<ClientListener> listener = conn->listener.lock();
        if (listener == nullptr) {
            log_conn(this, conn, dbg, "Listener was deleted");
            upstream->close_connection(id, false, true);
            assert(0);
            break;
        }

        switch (conn->state) {
        case CONNS_CONNECTED: {
            listener->consume(conn->client_id, event->length);

            size_t server_can_send = upstream->available_to_send(conn->server_id);
            listener->turn_read(conn->client_id, server_can_send > 0);

            if (event->length > 0) {
                log_conn(this, conn, trace, "{} bytes sent to server (server side can send {} bytes)", event->length,
                        server_can_send);
            }
            break;
        }
        default:
            // do nothing
            break;
        }
        break;
    }
    case SERVER_EVENT_GET_AVAILABLE_TO_SEND: {
        auto *event = (ServerAvailableToSendEvent *) data;
        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_server_id, event->id);
        if (conn == nullptr) {
            break;
        }
        if (std::shared_ptr<ClientListener> listener = conn->listener.lock(); listener != nullptr) {
            event->length = listener->flow_control_info(conn->client_id).send_buffer_size;
        }
        break;
    }
    case SERVER_EVENT_ERROR: {
        const ServerError *event = (ServerError *) data;

        if (event->id == NON_ID) {
            close_client_side(this, upstream.get());
            break;
        }

        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_server_id, event->id);
        if (conn == nullptr) {
            destroy_connection(this, NON_ID, event->id);
            break;
        }

        bool need_close_client_side = true;

        switch (conn->state) {
        case CONNS_WAITING_RESPONSE: {
            log_conn(this, conn, dbg, "Failed to make tunnel: {} ({})", safe_to_string_view(event->error.text),
                    event->error.code);
            break;
        }
        case CONNS_WAITING_RESPONSE_MIGRATING: {
            log_conn(this, conn, dbg, "Failed to switch upstream: {} ({})", safe_to_string_view(event->error.text),
                    event->error.code);

            VpnConnection *src_conn =
                    vpn_connection_get_by_id(this->connections.by_client_id, conn->migrating_client_id);
            if (src_conn == nullptr) {
                // do nothing
            } else {
                upstream->close_connection(src_conn->server_id, false, true);
            }

            if (std::shared_ptr<ServerUpstream> conn_upstream = conn->upstream.lock(); conn_upstream != nullptr) {
                conn_upstream->close_connection(conn->server_id, false, true);
            }
            need_close_client_side = false;
            break;
        }
        default:
            log_conn(this, conn, dbg, "Server closed connection in state: {}, with error: {} ({})",
                    magic_enum::enum_name(conn->state), safe_to_string_view(event->error.text), event->error.code);
            break;
        }

        if (need_close_client_side) {
            if (nullptr != vpn_connection_get_by_id(this->connections.by_client_id, conn->client_id)) {
                vpn_connection_remove(this->connections.by_server_id, conn->server_id);
                close_client_side_connection(this, conn, event->error.code, false);
            } else {
                destroy_connection(this, conn->client_id, conn->server_id);
            }
        }

        break;
    }
    case SERVER_EVENT_ECHO_REPLY: {
        auto &reply = *(IcmpEchoReply *) data;
        switch (this->icmp_manager.register_reply(reply)) {
        case IM_MSGS_PASS:
            this->vpn->client_listener->process_icmp_reply(reply);
            break;
        case IM_MSGS_DROP:
            break;
        }
        break;
    }
    }
}

constexpr VpnConnectAction vpn_mode_to_action(VpnMode mode) {
    VpnConnectAction action = VPN_CA_DEFAULT;

    switch (mode) {
    case VPN_MODE_GENERAL:
        action = VPN_CA_FORCE_REDIRECT;
        break;
    case VPN_MODE_SELECTIVE:
        action = VPN_CA_FORCE_BYPASS;
        break;
    }

    return action;
}

constexpr VpnConnectAction invert_action(VpnConnectAction action) {
    switch (action) {
    case VPN_CA_DEFAULT:
    case VPN_CA_REJECT:
        break;
    case VPN_CA_FORCE_BYPASS:
        action = VPN_CA_FORCE_REDIRECT;
        break;
    case VPN_CA_FORCE_REDIRECT:
        action = VPN_CA_FORCE_BYPASS;
        break;
    }

    return action;
}

static std::shared_ptr<ServerUpstream> select_upstream(
        const Tunnel *self, VpnConnectAction action, VpnConnection *conn) {
    switch (action) {
    case VPN_CA_DEFAULT:
        if (conn != nullptr) {
            if (conn->listener.lock().get() == self->dns_handler.get()) {
                return select_upstream(self, VPN_CA_FORCE_REDIRECT, nullptr);
            }
            if (conn->flags.test(CONNF_PLAIN_DNS_CONNECTION)) {
                return self->dns_handler;
            }
        }
        if (const sockaddr_storage * dst; // NOLINT(cppcoreguidelines-init-variables)
                conn != nullptr && conn->flags.test(CONNF_LOOKINGUP_DOMAIN) && conn->flags.test(CONNF_SUSPECT_EXCLUSION)
                && nullptr != (dst = std::get_if<sockaddr_storage>(&conn->addr.dst))
                && is_domain_scannable_port(sockaddr_get_port((sockaddr *) dst))) {
            return self->fake_upstream;
        }
        return select_upstream(self, vpn_mode_to_action(self->vpn->domain_filter.get_mode()), nullptr);
    case VPN_CA_FORCE_BYPASS:
        return self->vpn->bypass_upstream;
        break;
    case VPN_CA_FORCE_REDIRECT:
        return self->vpn->endpoint_upstream;
        break;
    case VPN_CA_REJECT:
        assert(0);
        break;
    }
    return nullptr;
}

/**
 * @return The result code which should be set to the event
 */
[[nodiscard]] static ssize_t initiate_connection_migration(
        Tunnel *self, VpnConnection *conn, std::shared_ptr<ServerUpstream> upstream, U8View packet) {
    if (upstream == nullptr) {
        log_conn(self, conn, dbg, "Can't start migration due to upstream isn't selected");
        return -1;
    }

    log_conn(self, conn, dbg, "Migrating to {} upstream",
            (upstream.get() == self->vpn->endpoint_upstream.get())         ? "VPN endpoint"
                    : (upstream.get() == self->vpn->bypass_upstream.get()) ? "direct"
                    : (upstream.get() == self->fake_upstream.get())        ? "fake"
                                                                           : "unknown");

    uint64_t server_id = upstream->open_connection(&conn->addr, conn->proto, {});
    if (server_id == NON_ID) {
        log_conn(self, conn, dbg, "Couldn't open connection on new upstream");
        return -1;
    }

    size_t processed = 0;

    VpnConnection *sw_conn = VpnConnection::make(NON_ID, conn->addr, conn->proto);
    sw_conn->server_id = server_id;
    sw_conn->listener = conn->listener;
    sw_conn->upstream = upstream;
    sw_conn->state = CONNS_WAITING_RESPONSE_MIGRATING;
    sw_conn->flags.set(CONNF_LOOKINGUP_DOMAIN, conn->flags.test(CONNF_LOOKINGUP_DOMAIN));
    sw_conn->migrating_client_id = conn->client_id;
    sw_conn->app_name = conn->app_name;
    sw_conn->domain_lookuper_result = conn->domain_lookuper_result;
    add_connection(self, sw_conn);
    if (conn->proto == IPPROTO_UDP) {
        // do not turn off reads on migrating UDP connections,
        // because otherwise the unread packets might be dropped
        conn->buffered_packets.emplace_back(packet.begin(), packet.end());
        processed = packet.size();
    } else {
        sw_conn->buffered_packets = std::move(conn->buffered_packets);
        if (std::shared_ptr<ClientListener> listener = conn->listener.lock(); listener != nullptr) {
            listener->turn_read(conn->client_id, false);
        } else {
            log_conn(self, conn, dbg, "Listener was deleted");
            return -1;
        }
    }

    conn->state = CONNS_CONNECTED_MIGRATING;
    if (std::shared_ptr<ServerUpstream> conn_upstream = conn->upstream.lock(); conn_upstream != nullptr) {
        conn_upstream->update_flow_control(conn->server_id, {});
    }

    log_conn(self, sw_conn, trace, "Connecting...");
    return processed;
}

std::optional<VpnConnectAction> Tunnel::finalize_connect_action(ConnectRequestResult request_result) const {
    VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_client_id, request_result.id);
    if (conn == nullptr) {
        log_tun(this, dbg, "Got complete connect request result for inexistent or already closed connection: {}",
                request_result.id);
        return std::nullopt;
    }

    if (!request_result.appname.empty()) {
        conn->app_name = std::move(request_result.appname);
    }
#ifdef _WIN32
    std::string_view process_name = conn->app_name;
    if (auto backslash_pos = process_name.rfind('\\'); backslash_pos != std::string_view::npos) {
        process_name.remove_prefix(backslash_pos + 1);
        conn->app_name = process_name;
    }
#endif
    conn->uid = request_result.uid;

    const DomainFilter *filter = &this->vpn->domain_filter;
    if ((request_result.action.has_value() && request_result.action.value() != VPN_CA_DEFAULT)
            || conn->flags.test(CONNF_PLAIN_DNS_CONNECTION)) {
        conn->action = request_result.action;
    } else if (const sockaddr_storage *dst = std::get_if<sockaddr_storage>(&conn->addr.dst); dst != nullptr) {
        DomainFilterMatchResult filter_result = filter->match_tag(conn->make_tag());
        switch (filter_result.status) {
        case DFMS_DEFAULT:
            conn->action = request_result.action;
            break;
        case DFMS_EXCLUSION: {
            log_conn(this, conn, dbg, "Connection will be excluded");
            conn->action = invert_action(vpn_mode_to_action(this->vpn->domain_filter.get_mode()));
            report_connection_info(
                    this, conn, filter_result.domain.has_value() ? filter_result.domain->c_str() : nullptr);
            break;
        }
        case DFMS_SUSPECT_EXCLUSION:
            if (is_domain_scannable_port(sockaddr_get_port((sockaddr *) dst))) {
                log_conn(this, conn, dbg, "Connection may target excluded host");
                conn->flags.set(CONNF_SUSPECT_EXCLUSION);
            }
            break;
        }
    } else if (const NamePort *dst = std::get_if<NamePort>(&conn->addr.dst); dst != nullptr) {
        switch (this->vpn->domain_filter.match_domain(dst->name)) {
        case DFMS_SUSPECT_EXCLUSION:
#ifndef NDEBUG
            assert(0);
            break;
#else
            [[fallthrough]];
#endif
        case DFMS_DEFAULT:
            conn->action = request_result.action;
            break;
        case DFMS_EXCLUSION:
            conn->action = invert_action(vpn_mode_to_action(this->vpn->domain_filter.get_mode()));
            report_connection_info(this, conn, dst->name.c_str());
            break;
        }
    }

    log_conn(this, conn, dbg, "Final action: {}",
            conn->action.has_value() ? magic_enum::enum_name(conn->action.value()) : "<none>");
    return conn->action;
}

static std::optional<sockaddr_storage> select_resolved_destination_address(
        const Tunnel *self, const VpnConnection *conn, std::span<sockaddr_storage> addresses) {
    for (sockaddr_storage address : addresses) {
        log_conn(self, conn, dbg, "Checking: {}", sockaddr_ip_to_str((sockaddr *) &address));

        sockaddr_set_port((sockaddr *) &address, std::get<NamePort>(conn->addr.dst).port);
        VpnConnectAction action = VPN_CA_DEFAULT;
        // if the action was default, check if the address matches exclusions
        if (!conn->flags.test(CONNF_FORCIBLY_BYPASSED) && !conn->flags.test(CONNF_FORCIBLY_REDIRECTED)) {
            DomainFilterMatchResult filter_result = self->vpn->domain_filter.match_tag(SockAddrTag{address});
            switch (filter_result.status) {
            case DFMS_DEFAULT:
                // neither the domain name nor resolved address matched against exclusions,
                // continue with the default action
            case DFMS_SUSPECT_EXCLUSION:
                // we already know the domain name, so ignore suspicions
                break;
            case DFMS_EXCLUSION:
                log_conn(self, conn, dbg, "Resolved address matches exclusions");
                action = invert_action(vpn_mode_to_action(self->vpn->domain_filter.get_mode()));
                break;
            }
        }

        std::shared_ptr<ServerUpstream> upstream = select_upstream(self, action, nullptr);
        if (upstream != nullptr
                && upstream->ip_version_availability.test(sa_family_to_ip_version(address.ss_family).value())) {
            return address;
        }

        log_conn(self, conn, dbg, "{} is unreachable", sockaddr_to_str((sockaddr *) &address));
    }

    return std::nullopt;
}

static void on_destination_resolve_result(void *arg, VpnDnsResolveId id, VpnDnsResolverResult result) {
    auto *self = (Tunnel *) arg;

    auto it = self->dns_resolve_waiters.find(id);
    if (it == self->dns_resolve_waiters.end()) {
        log_tun(self, dbg, "Resolve result waiter isn't found: id={}", id);
        self->dns_resolver->cancel(id);
        return;
    }

    // `close_client_side_connection()` can invalidate `it`
    DnsResolveWaiter &waiter = it->second;
    VpnConnection *conn = vpn_connection_get_by_id(self->connections.by_client_id, waiter.conn_client_id);
    if (conn == nullptr) {
        log_tun(self, dbg, "Connection is closed: resolve_id={} conn_id=[L:{}]", id, waiter.conn_client_id);
        self->dns_resolver->cancel(id);
        self->dns_resolve_waiters.erase(it);
        return;
    }

    if (conn->state != CONNS_WAITING_RESOLVE) {
        log_conn(self, conn, dbg, "Connection has invalid state: {}", magic_enum::enum_name(conn->state));
        self->dns_resolver->cancel(id);
        self->dns_resolve_waiters.erase(it);
        close_client_side_connection(self, conn, ag::utils::AG_ECONNREFUSED, false);
        return;
    }

    if (std::holds_alternative<VpnDnsResolverFailure>(result)) {
        log_conn(self, conn, dbg, "Couldn't resolve destination hostname");
        self->dns_resolve_waiters.erase(it);
        close_client_side_connection(self, conn, 0, false);
        return;
    }

    self->dns_resolver->cancel(id);
    self->dns_resolve_waiters.erase(it);

    std::optional<sockaddr_storage> maybe_address =
            select_resolved_destination_address(self, conn, std::get<VpnDnsResolverSuccess>(result).addresses);
    if (!maybe_address.has_value()) {
        log_conn(self, conn, dbg, "Suitable address not found");
        close_client_side_connection(self, conn, 0, false);
        return;
    }

    const sockaddr_storage &address = maybe_address.value();
    sockaddr_set_port((sockaddr *) &address, std::get<NamePort>(conn->addr.dst).port);
    log_conn(self, conn, dbg, "Resolved address: {}", sockaddr_to_str((sockaddr *) &address));

    VpnConnectAction action = VPN_CA_DEFAULT;
    if (conn->flags.test(CONNF_FORCIBLY_BYPASSED)) {
        action = VPN_CA_FORCE_BYPASS;
    } else if (conn->flags.test(CONNF_FORCIBLY_REDIRECTED)) {
        action = VPN_CA_FORCE_REDIRECT;
    } else {
        DomainFilterMatchResult filter_result = self->vpn->domain_filter.match_tag(SockAddrTag{address});
        switch (filter_result.status) {
        case DFMS_DEFAULT:
            // neither the domain name nor resolved address matched against exclusions,
            // continue with the default action
        case DFMS_SUSPECT_EXCLUSION:
            // we already know the domain name, so ignore suspicions
            break;
        case DFMS_EXCLUSION:
            log_conn(self, conn, dbg, "Resolved address matches exclusions");
            action = invert_action(vpn_mode_to_action(self->vpn->domain_filter.get_mode()));
            break;
        }
    }

    std::shared_ptr<ServerUpstream> upstream = select_upstream(self, action, nullptr);
    conn->upstream = upstream;
    conn->addr.dst = address;
    if (upstream != nullptr) {
        conn->server_id = upstream->open_connection(&conn->addr, conn->proto, conn->app_name);
    }
    if (conn->server_id != NON_ID) {
        conn->state = CONNS_WAITING_RESPONSE;
        log_conn(self, conn, trace, "Connecting...");
        add_connection(self, conn);
    } else {
        close_client_side_connection(self, conn, 0, false);
    }
}

static bool need_resolve_hostname(const Tunnel *self, VpnConnectAction action, const VpnConnection *conn) {
    const auto *dst = std::get_if<NamePort>(&conn->addr.dst);
    if (dst == nullptr) {
        return false;
    }

    if (conn->listener.lock() == self->vpn->dns_proxy_listener) {
        // Allow connections with domain as destination address from DnsLibs.
        // This prevents route looping requests from DnsLibs bootstrapper.
        return false;
    }

    // adjust action to an effective value
    switch (action) {
    case VPN_CA_DEFAULT:
        switch (self->vpn->domain_filter.match_domain(dst->name)) {
        case DFMS_DEFAULT:
            action = vpn_mode_to_action(self->vpn->domain_filter.get_mode());
            break;
        case DFMS_EXCLUSION:
        case DFMS_SUSPECT_EXCLUSION:
            action = invert_action(vpn_mode_to_action(self->vpn->domain_filter.get_mode()));
            break;
        }
        break;
    case VPN_CA_FORCE_BYPASS:
    case VPN_CA_FORCE_REDIRECT:
    case VPN_CA_REJECT:
        break;
    }

    switch (action) {
    case VPN_CA_DEFAULT:
    case VPN_CA_REJECT:
        assert(0); // should not get here
        return false;
    case VPN_CA_FORCE_BYPASS:
        return true;
    case VPN_CA_FORCE_REDIRECT:
        return self->vpn->dns_proxy_listener != nullptr;
    }
}

static bool is_destination_reachable(const Tunnel *self, VpnConnection *conn, ServerUpstream *upstream) {
    const sockaddr_storage *dst = std::get_if<sockaddr_storage>(&conn->addr.dst);
    if (!dst) {
        // Let's assume a hostname+port pair is reachable.
        return true;
    }

    std::optional<IpVersion> ipv = sa_family_to_ip_version(dst->ss_family);
    if (!ipv) {
        // Let's assume an invalid address is unreachable.
        return false;
    }

    if (conn->flags.test(CONNF_SUSPECT_EXCLUSION)
            // if upstream is not yet connected, it will be decided later whether to
            // reject or bypass the connection
            && ((self->vpn->endpoint_upstream != nullptr
                        && !self->vpn->endpoint_upstream->ip_version_availability.test(*ipv))
                    || (self->vpn->bypass_upstream != nullptr
                            && !self->vpn->bypass_upstream->ip_version_availability.test(*ipv)))) {
        // Suspecting that the connection targets an excluded domain, the library
        // accepts it creating a fake connection, reads some outgoing packets to find
        // out if the guess is true, and in case it is, the connection is migrated
        // to the needed upstream. At this point, the library is no longer able to
        // notify the client of the unreachable status.
        //
        // To avoid that, all suspicious connections are rejected with the unreachable
        // status if an IP version is not available on any of the "real" upstreams.
        return false;
    }

    if (upstream != nullptr && !upstream->ip_version_availability.test(*ipv)) {
        return false;
    }

    return true;
}

void Tunnel::complete_connect_request(uint64_t id, std::optional<VpnConnectAction> action) {
    VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_client_id, id);
    if (conn == nullptr) {
        log_tun(this, dbg, "Got complete connect request result for inexistent or already closed connection: {}", id);
        return;
    }

    if (vpn_handler_profiling_enabled()) {
        auto now = std::chrono::high_resolution_clock::now();
        int64_t dt = std::chrono::duration_cast<std::chrono::nanoseconds>(now - conn->requested_at).count();
        if (int64_t threshold = vpn_handler_profiling_threshold_ns(); dt > threshold) {
            log_tun(this, warn, "Connection request [L:{}] completed after {} ms, threshold: {} ms", conn->client_id,
                    dt / 1'000'000.0, threshold / 1'000'000.0);
        }
    }

    switch (action.value_or(VPN_CA_DEFAULT)) {
    case VPN_CA_FORCE_BYPASS:
        conn->flags.set(CONNF_FORCIBLY_BYPASSED);
        break;
    case VPN_CA_FORCE_REDIRECT:
        conn->flags.set(CONNF_FORCIBLY_REDIRECTED);
        break;
    case VPN_CA_DEFAULT:
        conn->flags.set(CONNF_LOOKINGUP_DOMAIN,
                std::holds_alternative<sockaddr_storage>(conn->addr.dst)
                        && !conn->flags.test(CONNF_PLAIN_DNS_CONNECTION));
        action = VPN_CA_DEFAULT;
        break;
    case VPN_CA_REJECT:
        close_client_side_connection(this, conn, utils::AG_ECONNREFUSED, true);
        return;
    }

    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    std::shared_ptr<ServerUpstream> upstream = select_upstream(this, action.value(), conn);
    if (!is_destination_reachable(this, conn, upstream.get())) {
        log_conn(this, conn, dbg, "Closing as destination is considered unreachable");
        close_client_side_connection(this, conn, AG_ENETUNREACH, true);
        return;
    }

    if (need_resolve_hostname(this, action.value(), conn)) { // NOLINT(bugprone-unchecked-optional-access)
        std::optional<VpnDnsResolveId> resolve_id =
                this->dns_resolver->resolve(VDRQ_FOREGROUND, std::get<NamePort>(conn->addr.dst).name,
                        VpnDnsResolver::RecordTypeSet{}.set(), {on_destination_resolve_result, this});
        if (!resolve_id.has_value()) {
            log_conn(this, conn, dbg, "Failed to start target name resolving");
            close_client_side_connection(this, conn, ag::utils::AG_ECONNREFUSED, true);
            return;
        }

        log_conn(this, conn, dbg, "Started resolving destination hostname");
        this->dns_resolve_waiters.emplace(resolve_id.value(), DnsResolveWaiter{.conn_client_id = conn->client_id});
        conn->state = CONNS_WAITING_RESOLVE;
        return;
    }

    conn->upstream = upstream;
    if (!this->endpoint_upstream_connected && upstream.get() == this->vpn->endpoint_upstream.get()) {
        log_conn(this, conn, dbg, "Rejecting connection redirected to endpoint we're not connected to");
        conn->upstream.reset();
        close_client_side_connection(this, conn, 0, true);
        return;
    }

    if (upstream != nullptr) {
        conn->flags.set(CONNF_FAKE_CONNECTION, this->fake_upstream.get() == upstream.get());
        conn->server_id = upstream->open_connection(&conn->addr, conn->proto, conn->app_name);
        if (conn->server_id == NON_ID) {
            log_conn(this, conn, dbg, "Upstream failed to open connection");
        }
    } else {
        log_conn(this, conn, dbg, "Upstream was not selected");
    }

    if (conn->server_id != NON_ID) {
        conn->state = CONNS_WAITING_RESPONSE;
        log_conn(this, conn, dbg, "Connecting...");
        add_connection(this, conn);
        if (conn->flags.test(CONNF_PLAIN_DNS_CONNECTION)) {
            if (conn->listener.lock().get() == this->dns_resolver.get()) {
                this->dns_handler->notify_vpn_resolver_connection(conn->server_id);
            }
        }
    } else {
        close_client_side_connection(this, conn, 0, true);
    }
}

void Tunnel::reset_connections(int uid) {
    log_tun(this, dbg, "Resetting connections with uid {}", uid);
    khash_t(connections_by_id) *table = this->connections.by_client_id;

    // `close_client_side_connection()` might insert new connections into the table,
    // leading to undefined behaviour if called within the foreach loop
    std::vector<uint64_t> ids;
    ids.reserve(kh_size(table));

    vpn_connections_foreach(table, [&](VpnConnection *conn) {
        std::shared_ptr<ClientListener> listener = conn->listener.lock();
        if ((uid == -1 || conn->uid == uid) && listener.get() != this->dns_resolver.get()
                && (listener.get() != this->dns_handler.get()
                        || !this->dns_handler->is_vpn_resolver_connection(conn->client_id))) {
            ids.push_back(conn->client_id);
        }
    });

    for (uint64_t id : ids) {
        if (VpnConnection *conn = vpn_connection_get_by_id(table, id)) {
            close_client_side_connection(this, conn, -1, false);
        }
    }
}

void Tunnel::reset_connections(ClientListener *listener) {
    log_tun(this, dbg, "Resetting connections by listener");

    khash_t(connections_by_id) *table = this->connections.by_client_id;
    std::vector<uint64_t> ids;
    ids.reserve(kh_size(table));

    vpn_connections_foreach(table, [&](VpnConnection *conn) {
        if (conn->listener.lock().get() == listener) {
            ids.push_back(conn->client_id);
        }
    });

    for (uint64_t conn_id : ids) {
        if (VpnConnection *conn = vpn_connection_get_by_id(table, conn_id); conn != nullptr) {
            close_client_side_connection(this, conn, -1, false);
        }
    }
}

void Tunnel::reset_connection(uint64_t client_id) {
    if (VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_client_id, client_id)) {
        log_tun(this, dbg, "Resetting connection with client id: {}", client_id);
        close_client_side_connection(this, conn, -1, false);
    } else {
        log_tun(this, dbg, "Connection with client id: {} not found", client_id);
    }
}

void Tunnel::on_before_endpoint_disconnect(ServerUpstream *upstream) {
    if (this->vpn->endpoint_upstream.get() != upstream) {
        return;
    }
    this->dns_resolver->stop_resolving();
    this->repeat_exclusions_resolve_task.reset();

    std::vector<uint64_t> ids;
    vpn_connections_foreach(this->connections.by_client_id, [&ids](VpnConnection *conn) {
        ids.push_back(conn->client_id);
    });

    for (uint64_t id : ids) {
        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_client_id, id);
        if (conn != nullptr) {
            close_client_side_connection(this, conn, -1, false);
        }
    }

    this->endpoint_upstream_connected = false;
}

void Tunnel::on_after_endpoint_disconnect(ServerUpstream *upstream) { // NOLINT(readability-make-member-function-const)
    if (this->connections.by_client_id == nullptr) {
        return;
    }

    vpn_connections_foreach(this->connections.by_client_id, [upstream](VpnConnection *conn) {
        if (conn->upstream.lock().get() == upstream) {
            conn->flags.set(CONNF_SESSION_CLOSED);
            if (std::shared_ptr<ClientListener> listener = conn->listener.lock(); listener != nullptr) {
                listener->turn_read(conn->client_id, false);
            }
        }
    });

    if (upstream == this->vpn->endpoint_upstream.get()) {
        if (this->dns_resolver != nullptr) {
            this->dns_resolver->deinit();
        }

        if (this->fake_upstream != nullptr) {
            // just re-open the session to close all the currently open fake connections
            this->fake_upstream->close_session();
            this->fake_upstream->open_session();
        }
    }
}

void Tunnel::on_exclusions_updated() {
    // exclusions are resolved in background
    this->dns_resolver->stop_resolving_queues(1 << VDRQ_BACKGROUND);

    if (this->vpn->endpoint_upstream != nullptr) {
        std::vector<std::string_view> names = this->vpn->domain_filter.get_resolvable_exclusions();
        for (std::string_view name : names) {
            if (!this->dns_resolver->resolve(VDRQ_BACKGROUND, std::string(name)).has_value()) {
                log_tun(this, dbg, "Failed to start resolve of {}", name);
            }
        }
    } else {
        log_tun(this, dbg, "Skipping exclusions resolve as there's no connection to endpoint");
    }

    using namespace std::chrono;
    this->repeat_exclusions_resolve_task = event_loop::schedule(this->vpn->parameters.ev_loop,
            {
                    this,
                    [](void *arg, TaskId) {
                        auto *self = (Tunnel *) arg;
                        self->repeat_exclusions_resolve_task.release();
                        self->on_exclusions_updated();
                    },
            },
            EXCLUSIONS_RESOLVE_PERIOD);
}

bool Tunnel::should_complete_immediately(uint64_t client_id) const {
    const VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_client_id, client_id);
    // In general mode, conection requests suspected to be to an exclusion host should be completed
    // immediately -- don't wait for recovery to bypass a connection. In selective mode, it's the opposite.
    // Connections to the plain DNS port should be completed immediately: PlainDnsManager should decide
    // whether to reject or bypass a plain DNS request.
    return conn
            && (conn->flags.test(CONNF_SUSPECT_EXCLUSION) == (vpn->exclusions_mode == VPN_MODE_GENERAL)
                    || conn->addr.dstport() == dns_utils::PLAIN_DNS_PORT_NUMBER);
}

static VpnAddress tunnel_to_vpn_address(const TunnelAddress *tunnel) {
    VpnAddress vpn = {};

    if (const sockaddr_storage *addr = std::get_if<sockaddr_storage>(tunnel); addr != nullptr) {
        vpn.type = VPN_AT_ADDR;
        memcpy(&vpn.addr, addr, sizeof(vpn.addr));
    } else if (const NamePort *addr = std::get_if<NamePort>(tunnel); addr != nullptr) {
        vpn.type = VPN_AT_HOST;
        vpn.host.name = {(char *) addr->name.c_str(), uint32_t(addr->name.length())};
        vpn.host.port = addr->port;
    } else {
        assert(0);
    }

    return vpn;
}

// @note: close server-side connections with a context switch here to avoid calling server-side
// close while we are still in its handler
// no need to do it in `upstream_handler`, it's safe to do it on one side
void Tunnel::listener_handler(const std::shared_ptr<ClientListener> &listener, ClientEvent what, void *data) {
    switch (what) {
    case CLIENT_EVENT_CONNECT_REQUEST: {
        const ClientConnectRequest *client_event = (ClientConnectRequest *) data;

        TunnelAddressPair client_event_addr = {client_event->src, *client_event->dst};
        if (const auto *addr = std::get_if<NamePort>(client_event->dst); addr != nullptr) {
            if (utils::is_valid_ip4(addr->name)) {
                auto dst = sockaddr_from_str(AG_FMT("{}:{}", addr->name, addr->port).c_str());
                client_event_addr = {client_event->src, (sockaddr *) &dst};
            } else if (utils::is_valid_ip6(addr->name)) {
                auto dst = sockaddr_from_str(AG_FMT("[{}]:{}", addr->name, addr->port).c_str());
                client_event_addr = {client_event->src, (sockaddr *) &dst};
            }
        }

        VpnConnection *conn = VpnConnection::make(client_event->id, client_event_addr, client_event->protocol);
        conn->listener = listener;
        conn->app_name = client_event->app_name;
        conn->flags.set(CONNF_FIRST_PACKET);
        if (vpn_handler_profiling_enabled()) {
            conn->requested_at = std::chrono::high_resolution_clock::now();
        }

        log_conn(this, conn, dbg, "New client connection request: {}->{} (proto: {})",
                sockaddr_to_str(client_event->src), tunnel_addr_to_str(&client_event_addr.dst), client_event->protocol);

        add_connection(this, conn);

        if (listener.get() == this->dns_resolver.get()) {
            this->complete_connect_request(conn->client_id, std::nullopt);
            return;
        }

        if (listener.get() == this->vpn->dns_proxy_listener.get() || listener.get() == this->dns_handler.get()) {
            this->complete_connect_request(conn->client_id, VPN_CA_FORCE_REDIRECT);
            return;
        }

        // Plain DNS connections are routed by `PlainDnsManager`
        if (!conn->flags.test(CONNF_PLAIN_DNS_CONNECTION)) {
            if (const auto *addr = (sockaddr *) std::get_if<sockaddr_storage>(client_event->dst);
                    addr != nullptr && sockaddr_is_loopback(addr)) {
                log_conn(this, conn, dbg, "Routing loopback connection directly");
                this->complete_connect_request(conn->client_id, VPN_CA_FORCE_BYPASS);
                return;
            }
        }

        VpnAddress dst = tunnel_to_vpn_address(&client_event_addr.dst);
        VpnConnectRequestEvent vpn_event = {
                client_event->id, client_event->protocol, client_event->src, &dst, conn->app_name.c_str()};
        // result will come in `complete_connect_request`
        vpn->parameters.handler.func(vpn->parameters.handler.arg, vpn_client::EVENT_CONNECT_REQUEST, &vpn_event);
        break;
    }
    case CLIENT_EVENT_CONNECTION_ACCEPTED: {
        uint64_t id = *(uint64_t *) data;

        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_client_id, id);
        if (conn == nullptr) {
            log_tun(this, dbg, "Got accepted event for inexistent or already closed connection: {}", id);
            assert(0);
            break;
        }

        if (conn->state != CONNS_WAITING_ACCEPT) {
            log_conn(this, conn, dbg, "Connection has invalid state: {} (event={}), will be closed",
                    magic_enum::enum_name(conn->state), magic_enum::enum_name(what));
            close_client_side_connection(this, conn, -1, true);
            break;
        }

        conn->state = CONNS_CONNECTED;
        listener->turn_read(id, true);

        if (std::shared_ptr<ServerUpstream> upstream = conn->upstream.lock(); upstream != nullptr) {
            upstream->update_flow_control(conn->server_id, listener->flow_control_info(conn->client_id));

            if (listener.get() == this->vpn->client_listener.get()
                    && conn->upstream.lock().get() == this->vpn->endpoint_upstream.get()) {
                conn->flags.set(CONNF_MONITOR_STATS);
                this->statistics_monitor->register_conn(id);
            }
        }
        break;
    }
    case CLIENT_EVENT_CONNECTION_CLOSED: {
        uint64_t id = *(uint64_t *) data;

        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_client_id, id);
        if (conn == nullptr) {
            break;
        }

        log_conn(this, conn, dbg, "Connection closed");
        if (conn->flags.test(CONNF_SESSION_CLOSED)
                || nullptr == vpn_connection_get_by_id(this->connections.by_server_id, conn->server_id)) {
            destroy_connection(this, id, conn->server_id);
            break;
        }

        std::shared_ptr<ServerUpstream> upstream = conn->upstream.lock();
        if (upstream == nullptr) {
            destroy_connection(this, id, conn->server_id);
            break;
        }

        if (conn->state == CONNS_CONNECTED) {
            upstream->update_flow_control(conn->server_id, {});
        }

        vpn_connection_remove(this->connections.by_client_id, id);
        upstream->close_connection(conn->server_id, true, true);

        break;
    }
    case CLIENT_EVENT_READ: {
        auto *event = (ClientRead *) data;
        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_client_id, event->id);
        if (conn == nullptr) {
            log_tun(this, dbg, "Got data from client for inexistent or already closed connection: {}", event->id);
            event->result = -1;
            assert(0);
            break;
        }

        std::shared_ptr<ServerUpstream> upstream = conn->upstream.lock();
        if (upstream == nullptr) {
            log_conn(this, conn, dbg, "Upstream was deleted");
            event->result = -1;
            assert(0);
            break;
        }

        if (conn->flags.test(CONNF_LOOKINGUP_DOMAIN)) {
            bool migrate_to_another_upstream = false;
            AfterLookuperAction alua = pass_through_lookuper(this, conn, DLUPD_OUTGOING, event->data, event->length);
            log_conn(this, conn, dbg, "alua={}", magic_enum::enum_name(alua));
            switch (alua) {
            case ALUA_DONE:
                conn->flags.reset(CONNF_LOOKINGUP_DOMAIN);
                break;
            case ALUA_PASS:
                break;
            case ALUA_DROP: {
                log_conn(this, conn, trace, "Dropping packet without closing connection, length: {}", event->length);
                event->result = event->length;
                return;
            }
            case ALUA_WANT_MORE: {
                // If tunnel faced with Anti-Dpi which can split ClientHello into parts, it needs to wait other parts
                // of ClientHello message (max - 3 parts)
                static constexpr int MAX_LOOKUP_ATTEMPTS = 3;
                if (conn->lookup_attempts_num++ < MAX_LOOKUP_ATTEMPTS) {
                    log_conn(this, conn, trace, "Adding pending packet, length: {}", event->length);
                    conn->buffered_packets.emplace_back(event->data, event->data + event->length);
                    event->result = event->length;
                    return;
                }
                log_conn(this, conn, trace, "Exceeded the number of domain lookup attempts");
                break;
            }
            case ALUA_SHUTDOWN:
                conn->action = invert_action(vpn_mode_to_action(this->vpn->domain_filter.get_mode()));
                conn->flags.reset(CONNF_LOOKINGUP_DOMAIN);
                migrate_to_another_upstream = true;
                break;
            case ALUA_BLOCK:
                log_conn(this, conn, dbg, "Dropped QUIC connection");
                listener->turn_read(conn->client_id, false);
                close_client_side_connection(this, conn, -1, true);
                event->result = -1;
                return;
            }

            report_connection_info(this, conn, conn->domain_lookuper_result.domain.c_str());
            if (migrate_to_another_upstream) {
                if (!conn->flags.test(CONNF_FIRST_PACKET)) {
                    log_conn(this, conn, dbg, "Can't switch upstream in the middle of handshake");
                    listener->turn_read(conn->client_id, false);
                    upstream->update_flow_control(conn->server_id, {});
                    upstream->close_connection(conn->server_id, false, true);
                    break;
                }
                auto upstream_to_migrate = select_upstream(this, conn->action.value(), conn);
                log_conn(this, conn, dbg, "Client: Connection had been routed {}, migrating to {}",
                        (upstream.get() == this->vpn->endpoint_upstream.get())         ? "through VPN endpoint"
                                : (upstream.get() == this->vpn->bypass_upstream.get()) ? "directly to target host"
                                : (upstream.get() == this->fake_upstream.get())        ? "through fake endpoint"
                                                                                       : "through unknown endpoint",
                        (upstream_to_migrate.get() == this->vpn->endpoint_upstream.get())         ? "Endpoint upstream"
                                : (upstream_to_migrate.get() == this->vpn->bypass_upstream.get()) ? "Bypass upstream"
                                : (upstream_to_migrate.get() == this->fake_upstream.get())        ? "Fake upstream"
                                                                                                  : "unknown upstream");
                event->result = initiate_connection_migration(
                        this, conn, std::move(upstream_to_migrate), {event->data, event->length});
                break;
            }
        }

        if (conn->flags.test(CONNF_FAKE_CONNECTION)) {
            // assume that SNI (in case of TLS) or host name (in case of plain HTTP) comes in
            // the first packet
            log_conn(this, conn, dbg,
                    "Couldn't find domain name for suspect-to-be-exclusion connection, routing it as usual ({})",
                    encode_to_hex({event->data, std::min(event->length, size_t(517))}));
            conn->flags.reset(CONNF_FAKE_CONNECTION);
            conn->flags.reset(CONNF_SUSPECT_EXCLUSION);
            event->result = initiate_connection_migration(
                    this, conn, select_upstream(this, VPN_CA_DEFAULT, conn), {event->data, event->length});
            break;
        }

        conn->flags.reset(CONNF_FIRST_PACKET);
        conn->flags.reset(CONNF_FAKE_CONNECTION);

        switch (conn->state) {
        case CONNS_CONNECTED: {
            if (!conn->buffered_packets.empty()) {
                if (!send_buffered_data(this, conn->client_id)) {
                    // connection has already closed
                    event->result = -1;
                    return;
                }
            }
            log_conn(this, conn, trace, "Sending {} bytes", event->length);
            event->result = (int) upstream->send(conn->server_id, event->data, event->length);
            if (event->result > 0 || (size_t) event->result == event->length) {
                conn->outgoing_bytes += event->result;
                if (conn->flags.test(CONNF_MONITOR_STATS)) {
                    this->statistics_monitor->update_upload(conn->client_id, event->result);
                }
                size_t server_can_send = upstream->available_to_send(conn->server_id);
                log_conn(this, conn, trace, "Server side can send {} bytes", server_can_send);
                listener->turn_read(conn->client_id, server_can_send > 0);
            } else if (event->result == 0) {
                listener->turn_read(conn->client_id, false);
            } else if (event->result < 0) {
                log_conn(this, conn, dbg, "Failed to send data from client");
                // connection will be closed inside listener
            }
            break;
        }
        case CONNS_CONNECTED_MIGRATING: {
            if (conn->proto == IPPROTO_UDP) {
                conn->buffered_packets.emplace_back(event->data, event->data + event->length);
                break;
            }
            [[fallthrough]];
        }
        default:
            log_conn(this, conn, err, "Connection has invalid state: {} (event={})",
                    magic_enum::enum_name(conn->state).data(), magic_enum::enum_name(what).data());
            assert(0);
            event->result = -1;
            break;
        }

        break;
    }
    case CLIENT_EVENT_DATA_SENT: {
        const ClientDataSentEvent *event = (ClientDataSentEvent *) data;

        VpnConnection *conn = vpn_connection_get_by_id(this->connections.by_client_id, event->id);
        if (conn == nullptr) {
            log_tun(this, dbg, "Got client sent data event for inexistent or already closed connection: {}", event->id);
            assert(0);
            break;
        }

        std::shared_ptr<ServerUpstream> upstream = conn->upstream.lock();
        if (upstream == nullptr || conn->server_id == NON_ID) {
            // sometimes client can poll on not yet established connections
            break;
        }

        upstream->consume(conn->server_id, event->length);

        TcpFlowCtrlInfo info = listener->flow_control_info(conn->client_id);
        upstream->update_flow_control(conn->server_id, info);

        if (event->length > 0) {
            log_conn(this, conn, trace, "{} bytes sent to client (client side can send {} bytes)", event->length,
                    info.send_buffer_size);
        }
        break;
    }
    case CLIENT_EVENT_OUTPUT: {
        vpn_client::Handler *vpn_handler = &this->vpn->parameters.handler;
        vpn_handler->func(vpn_handler->arg, vpn_client::EVENT_OUTPUT, data);
        break;
    }
    case CLIENT_EVENT_ICMP_ECHO_REQUEST: {
        auto *event = (IcmpEchoRequestEvent *) data;
        if (!this->vpn->may_send_icmp_request()) {
            log_tun(this, dbg, "Cannot send ICMP requests at the moment");
            event->result = -1;
            break;
        }

        switch (this->icmp_manager.register_request(event->request)) {
        case IM_MSGS_PASS: {
            VpnConnectAction action = VPN_CA_DEFAULT;
            switch (this->vpn->domain_filter.match_tag({event->request.peer}).status) {
            case DFMS_DEFAULT:
            case DFMS_SUSPECT_EXCLUSION:
                break;
            case DFMS_EXCLUSION:
                action = invert_action(vpn_mode_to_action(this->vpn->domain_filter.get_mode()));
                break;
            }
            if (std::shared_ptr<ServerUpstream> upstream = select_upstream(this, action, nullptr);
                    upstream != nullptr) {
                upstream->on_icmp_request(*event);
            }
            break;
        }
        case IM_MSGS_DROP:
            event->result = -1;
            break;
        }

        break;
    }
    }
}

void Tunnel::on_icmp_reply_ready(void *arg, const IcmpEchoReply &reply) {
    auto *self = (Tunnel *) arg;
    self->vpn->client_listener->process_icmp_reply(reply);
}

bool Tunnel::update_dns_handler_parameters() {
    auto parameters = make_dns_handler_parameters(this);
    if (!parameters.has_value()) {
        return false;
    }
    return this->dns_handler->update_parameters(std::move(*parameters));
}

static void fake_upstream_handler(void *arg, ServerEvent what, void *data) {
    auto *self = (Tunnel *) arg;
    self->upstream_handler(self->fake_upstream, what, data);
}

static void dns_upstream_upstream_handler(void *arg, ServerEvent what, void *data) {
    auto *self = (Tunnel *) arg;
    self->upstream_handler(self->dns_handler, what, data);
}

static void dns_upstream_listener_handler(void *arg, ClientEvent what, void *data) {
    auto *self = (Tunnel *) arg;
    self->listener_handler(self->dns_handler, what, data);
}

static void raise_statistics(Tunnel *self, const ConnectionStatistics &stats) {
    VpnTunnelConnectionStatsEvent event = {
            .id = stats.id,
            .upload = stats.upload,
            .download = stats.download,
    };
    const vpn_client::Handler &handler = self->vpn->parameters.handler;
    handler.func(handler.arg, vpn_client::EVENT_CONNECTION_STATS, &event);
}

bool Tunnel::init(VpnClient *vpn) {
    this->vpn = vpn;
    if (!this->icmp_manager.init({vpn->parameters.ev_loop}, {on_icmp_reply_ready, this})) {
        return false;
    }

    this->dns_resolver = std::make_unique<VpnDnsResolver>();
    if (this->dns_resolver->init(this->vpn, {dns_resolver_handler, this}) != ClientListener::InitResult::SUCCESS) {
        log_tun(this, warn, "Failed to initialize exclusions DNS resolver");
        this->deinit();
        assert(0);
        return false;
    }

    this->fake_upstream = std::make_unique<FakeUpstream>(VpnClient::next_upstream_id());
    if (!this->fake_upstream->init(this->vpn, {fake_upstream_handler, this}) || !this->fake_upstream->open_session()) {
        log_tun(this, warn, "Failed to initialize fake upstream");
        this->deinit();
        assert(0);
        return false;
    }

    auto dns_handler_parameters = make_dns_handler_parameters(this);
    if (!dns_handler_parameters.has_value()) {
        this->deinit();
        assert(0);
        return false;
    }
    this->dns_handler = std::make_shared<DnsHandler>(VpnClient::next_upstream_id(), std::move(*dns_handler_parameters));
    if (!this->dns_handler->initialize(
                this->vpn, {dns_upstream_upstream_handler, this}, {dns_upstream_listener_handler, this})) {
        log_tun(this, warn, "Failed to initialize the DNS handler");
        this->deinit();
        assert(0);
        return false;
    }

    this->statistics_monitor =
            std::make_unique<ConnectionStatisticsMonitor>(vpn->parameters.ev_loop, [this](ConnectionStatistics stats) {
                raise_statistics(this, stats);
            });

    return true;
}

static void clean_connection_table(Tunnel *tunnel, khash_t(connections_by_id) * table) {
    if (table != nullptr) {
        vpn_connections_foreach(table, [tunnel](VpnConnection *conn) {
            destroy_connection(tunnel, conn->client_id, conn->server_id);
        });
    }
}

void Tunnel::deinit() {
    log_tun(this, dbg, "...");

    this->endpoint_upstream_connected = false;
    if (this->dns_resolver != nullptr) {
        this->dns_resolver->deinit();
        this->dns_resolver.reset();
    }
    this->repeat_exclusions_resolve_task.reset();
    clean_connection_table(this, this->connections.by_client_id);
    clean_connection_table(this, this->connections.by_server_id);
    if (this->fake_upstream != nullptr) {
        this->fake_upstream->deinit();
        this->fake_upstream.reset();
    }
    this->icmp_manager.deinit();
    this->dns_handler.reset();
    this->statistics_monitor.reset();

    log_tun(this, dbg, "Done");
}

Tunnel::Tunnel()
        : connections({kh_init(connections_by_id), kh_init(connections_by_id)})
        , id(g_next_tunnel_id++) {
}

Tunnel::~Tunnel() {
    kh_destroy(connections_by_id, load_and_null(this->connections.by_client_id));
    kh_destroy(connections_by_id, load_and_null(this->connections.by_server_id));
}

} // namespace ag
