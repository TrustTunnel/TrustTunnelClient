#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <optional>

#include "common/socket_address.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

namespace ag {
namespace wire_utils {

static constexpr size_t IPV4_ADDR_SIZE = 4;
static constexpr size_t IPV6_ADDR_SIZE = 16;
static constexpr size_t PADDED_IP_SIZE = IPV6_ADDR_SIZE;
static constexpr size_t IPV4_6_SIZE_DIFF = IPV6_ADDR_SIZE - IPV4_ADDR_SIZE;

class Writer {
public:
    explicit Writer(U8View buffer)
            : m_buffer(buffer) {
    }

    ~Writer() = default;

    Writer(const Writer &) = delete;
    Writer &operator=(const Writer &) = delete;
    Writer(Writer &&) = delete;
    Writer &operator=(Writer &&) = delete;

    void put_u8(uint8_t val) {
        assert(m_buffer.size() >= sizeof(val));
        memcpy((void *) m_buffer.data(), &val, sizeof(val));
        m_buffer.remove_prefix(sizeof(val));
    }

    void put_u16(uint16_t val) {
        val = htons(val);
        assert(m_buffer.size() >= sizeof(val));
        memcpy((void *) m_buffer.data(), &val, sizeof(val));
        m_buffer.remove_prefix(sizeof(val));
    }

    void put_u32(uint32_t val) {
        assert(m_buffer.size() >= sizeof(val));
        val = htonl(val);
        memcpy((void *) m_buffer.data(), &val, sizeof(val));
        m_buffer.remove_prefix(sizeof(val));
    }

    void put_data(U8View d) {
        assert(m_buffer.size() >= d.size());
        memcpy((void *) m_buffer.data(), d.data(), d.size());
        m_buffer.remove_prefix(d.size());
    }

    void put_ip(const SocketAddress &addr) {
        this->put_data(addr.addr());
    }

    void put_ip_padded(const SocketAddress &addr) {
        if (addr.is_ipv4()) {
            // empty PADDING for ipv4
            static constexpr uint8_t PADDING[IPV4_6_SIZE_DIFF] = {};
            this->put_data({PADDING, std::size(PADDING)});
        }

        this->put_ip(addr);
    }

private:
    U8View m_buffer;
};

class Reader {
public:
    explicit Reader(U8View buffer)
            : m_buffer(buffer) {
    }

    void drain(size_t n) {
        m_buffer.remove_prefix(std::min(n, m_buffer.size()));
    }

    std::optional<uint8_t> get_u8() {
        uint8_t val; // NOLINT(cppcoreguidelines-init-variables)
        if (m_buffer.size() < sizeof(val)) {
            return std::nullopt;
        }
        memcpy(&val, m_buffer.data(), sizeof(val));
        m_buffer.remove_prefix(sizeof(val));
        return val;
    }

    std::optional<uint16_t> get_u16() {
        uint16_t val; // NOLINT(cppcoreguidelines-init-variables)
        if (m_buffer.size() < sizeof(val)) {
            return std::nullopt;
        }
        memcpy(&val, m_buffer.data(), sizeof(val));
        m_buffer.remove_prefix(sizeof(val));
        return ntohs(val);
    }

    std::optional<uint32_t> get_u32() {
        uint32_t val; // NOLINT(cppcoreguidelines-init-variables)
        if (m_buffer.size() < sizeof(val)) {
            return std::nullopt;
        }
        memcpy(&val, m_buffer.data(), sizeof(val));
        m_buffer.remove_prefix(sizeof(val));
        return ntohl(val);
    }

    std::optional<SocketAddress> get_ip(int family) {
        size_t ip_size = (family == AF_INET) ? IPV4_ADDR_SIZE : IPV6_ADDR_SIZE;
        if (m_buffer.size() < ip_size) {
            return std::nullopt;
        }

        SocketAddress addr({m_buffer.data(), ip_size}, 0);
        m_buffer.remove_prefix(ip_size);
        return addr;
    }

    std::optional<SocketAddress> get_ip_padded() {
        if (m_buffer.size() < PADDED_IP_SIZE) {
            return std::nullopt;
        }

        int family = AF_INET6;
        bool is_ipv4 = std::all_of(m_buffer.begin(), std::next(m_buffer.begin(), IPV4_6_SIZE_DIFF), [](int i) -> bool {
            return i == 0;
        }) && 0 != memcmp(m_buffer.data(), &in6addr_loopback, IPV6_ADDR_SIZE);
        if (is_ipv4) {
            m_buffer.remove_prefix(IPV4_6_SIZE_DIFF);
            family = AF_INET;
        }

        return this->get_ip(family);
    }

    std::optional<U8View> get_bytes(size_t size) {
        if (m_buffer.size() < size) {
            return std::nullopt;
        }

        U8View data = m_buffer.substr(0, size);
        m_buffer.remove_prefix(size);
        return data;
    }

    [[nodiscard]] U8View get_buffer() const {
        return m_buffer;
    }

private:
    U8View m_buffer;
};

} // namespace wire_utils
} // namespace ag
