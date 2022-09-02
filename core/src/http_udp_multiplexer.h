#pragma once

#include <chrono>
#include <optional>
#include <unordered_map>
#include <vector>

#include "vpn/internal/server_upstream.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/platform.h"

namespace ag {

// clang-format off
/*
 * Incoming UDP packet format (sent from the endpoint to us)
 * <p>
 * +----------+----------------+-------------+---------------------+------------------+---------+
 * |  Length  | Source address | Source port | Destination address | Destination port | Payload |
 * | 4 bytes  |  16 bytes      | 2 bytes     |  16 bytes           | 2 bytes          | N bytes |
 * +----------+----------------+-------------+---------------------+------------------+---------+
 * <p>
 * Outgoing UDP packet format (sent from us to the endpoint)
 * <p>
 * +----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+
 * |  Length  | Source address | Source port | Destination address | Destination port | App name len (L) | App name | Payload |
 * | 4 bytes  |  16 bytes      | 2 bytes     |  16 bytes           | 2 bytes          | 1 byte           | L bytes  | N bytes |
 * +----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+
 */
// clang-format on

static constexpr size_t UDPPKT_LENGTH_SIZE = 4;
static constexpr size_t UDPPKT_ADDR_SIZE = 16;
static constexpr size_t UDPPKT_PORT_SIZE = 2;
static constexpr size_t UDPPKT_IN_PREFIX_SIZE = UDPPKT_LENGTH_SIZE + 2 * (UDPPKT_ADDR_SIZE + UDPPKT_PORT_SIZE);

static constexpr size_t UDPPKT_APPLEN_SIZE = 1;
static constexpr size_t UDPPKT_APP_MAXSIZE = 255;

static constexpr size_t MAX_UDP_PAYLOAD_SIZE = 65535 - 8; // 8 bytes header
static constexpr size_t MAX_UDP_IN_PACKET_LENGTH = MAX_UDP_PAYLOAD_SIZE + UDPPKT_IN_PREFIX_SIZE - UDPPKT_LENGTH_SIZE;

struct HttpUdpMultiplexerParameters {
    ServerUpstream *parent = nullptr;
    /** @return stream id if sent successfully, none otherwise */
    std::optional<uint64_t> (*send_connect_request_callback)(
            ServerUpstream *upstream, const TunnelAddress *dst_addr, std::string_view app_name) = nullptr;
    /** @return 0 in case of success, non-zero value otherwise */
    int (*send_data_callback)(ServerUpstream *upstream, uint64_t stream_id, U8View data) = nullptr;
    void (*consume_callback)(ServerUpstream *upstream, uint64_t stream_id, size_t size) = nullptr;
};

/**
 * Multiplexes UDP traffic into a single HTTP stream
 */
class HttpUdpMultiplexer {
public:
    explicit HttpUdpMultiplexer(HttpUdpMultiplexerParameters parameters);
    ~HttpUdpMultiplexer();

    HttpUdpMultiplexer() = delete;
    HttpUdpMultiplexer(const HttpUdpMultiplexer &) = delete;
    HttpUdpMultiplexer &operator=(const HttpUdpMultiplexer &) = delete;
    HttpUdpMultiplexer(HttpUdpMultiplexer &&) = delete;
    HttpUdpMultiplexer &operator=(HttpUdpMultiplexer &&) = delete;

    /**
     * Reset multiplexer to idle state
     */
    void reset();

    /**
     * Close multiplexer with error (if non-zero)
     */
    void close(ServerError serv_err);

    /**
     * @brief Get id of stream which is currently used for UDP traffic
     */
    [[nodiscard]] std::optional<uint64_t> get_stream_id() const;

    /**
     * Open new UDP "connection"
     */
    bool open_connection(uint64_t conn_id, const TunnelAddressPair *addr, std::string_view app_name);

    /**
     * Close connection
     */
    void close_connection(uint64_t id, bool async);

    /**
     * Check if multiplexer has a connection with the given identifier
     * @return true if the connection exists, false otherwise
     */
    [[nodiscard]] bool check_connection(uint64_t id) const;

    /**
     * Send data via connection
     */
    ssize_t send(uint64_t id, U8View data);

    /**
     * Process data from VPN server
     * @return 0 if successful
     */
    int process_read_event(U8View data);

    /**
     * Handle response to stream creation request
     */
    void handle_response(const HttpHeaders *response);

    /**
     * Raise `SERVER_EVENT_DATA_SENT` for each connection that have non-zero sent bytes counter
     */
    void report_sent_bytes();

    /**
     * Turn on/off read events for connection.
     * Incoming packets are dropped in case read events are turned off.
     * @param id connection id
     * @param v whether read events should be tuned on/off
     */
    void set_read_enabled(uint64_t id, bool v);

    /**
     * Get the current number of UDP connections
     */
    [[nodiscard]] size_t connections_num() const;

private:
    enum MultiplexerState {
        MS_IDLE,
        MS_ESTABLISHED,
    };

    enum RecvConnectionState {
        RCS_IDLE,
        RCS_PAYLOAD,  // receiving payload
        RCS_DROPPING, // dropping data of invalid packet
    };

    struct Connection {
        bool read_enabled = false; // if true `SERVER_EVENT_READ` can be raised
        TunnelAddressPair addr;
        std::string app_name;
        size_t sent_bytes_since_flush = 0; // number of bytes sent since last socket write buffer flush
        std::chrono::time_point<std::chrono::steady_clock> timeout;
        event_loop::AutoTaskId open_task_id;
        event_loop::AutoTaskId close_task_id;
    };

    struct RecvConnection {
        RecvConnectionState state = RCS_IDLE;
        uint64_t id = NON_ID;
        size_t bytes_left = 0;
        std::vector<uint8_t> buffer;
    };

    struct PacketInfo {
        uint64_t id;           // NON_ID in case of error
        size_t payload_length; // raw payload length
    };

    HttpUdpMultiplexerParameters m_params = {};
    MultiplexerState m_state = MS_IDLE;
    uint64_t m_stream_id = 0;
    RecvConnection m_recv_connection = {};
    std::unordered_map<TunnelAddressPair, uint64_t> m_addr_to_id;
    std::unordered_map<uint64_t, Connection> m_connections;
    EventPtr m_timer_event = nullptr;
    std::optional<ServerError> m_pending_error;
    ag::Logger m_log{"UDP_MUX"};
    int m_id;

    static void complete_udp_connection(void *arg, TaskId task_id);
    static void timer_callback(evutil_socket_t, short, void *arg);
    [[nodiscard]] PacketInfo read_prefix(const std::vector<uint8_t> &data) const;
    /**
     * @return true if a connection with such id existed, false otherwise
     */
    bool clean_connection_data(uint64_t id);
    void close_connection(uint64_t id);
};

} // namespace ag
