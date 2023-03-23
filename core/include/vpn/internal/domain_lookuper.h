#pragma once

#include <memory>
#include <string>

#include "common/logger.h"
#include "vpn/utils.h"

namespace ag {

enum DomainLookuperStatus {
    DLUS_NOTFOUND,  // gave up looking for a domain name
    DLUS_FOUND,     // found a domain name
    DLUS_PASS,      // pass current packet, check the next one (client hello -> server hello)
    DLUS_WANT_MORE, // need more data to parse (client hello pt.1 -> client hello pt.2)
};

struct DomainLookuperResult {
    DomainLookuperStatus status = DLUS_NOTFOUND;
    std::string domain;
};

enum DomainLookuperPacketDirection {
    DLUPD_OUTGOING, // from client to server
    DLUPD_INCOMING, // from server to client
};

class DomainLookuper {
public:
    DomainLookuper();
    ~DomainLookuper();

    DomainLookuper(const DomainLookuper &) = delete;
    DomainLookuper &operator=(const DomainLookuper &) = delete;

    DomainLookuper(DomainLookuper &&) noexcept = delete;
    DomainLookuper &operator=(DomainLookuper &&) noexcept = delete;

    DomainLookuperResult proceed(DomainLookuperPacketDirection dir, int proto, const uint8_t *data, size_t length);

    void reset();

private:
    struct Context;
    std::unique_ptr<Context> m_context;
};

} // namespace ag
