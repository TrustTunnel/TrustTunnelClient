#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <ldns/ldns.h>

#include "vpn/utils.h"

namespace ag {
namespace dns_utils {

using LdnsPktPtr = DeclPtr<ldns_pkt, &ldns_pkt_free>;
using LdnsBufferPtr = DeclPtr<ldns_buffer, &ldns_buffer_free>;

static constexpr uint32_t PLAIN_DNS_PORT_NUMBER = 53;

enum RecordType {
    RT_A,
    RT_AAAA,
};

struct AnswerAddress {
    /// Raw IP address bytes
    std::vector<uint8_t> ip;
    /// Record TTL
    std::chrono::seconds ttl{};
};

struct InapplicablePacket {
    /// ID of the packet
    uint16_t id;
};

struct DecodedRequest {
    /// ID of the request
    uint16_t id;
    /// Record type of the question section.
    /// None in case the query type is not one of `RecordType`s.
    std::optional<RecordType> question_type;
    /// Domain name
    std::string name;
};

struct DecodedReply {
    /// ID of the reply
    uint16_t id;
    /// Record type of the question section.
    /// std::nullopt if not one of `ag::dns_utils::RecordType`.
    std::optional<RecordType> question_type;
    /// Domain name + CNAMEs (if some)
    std::vector<std::string> names;
    /// Resolved addresses info
    std::vector<AnswerAddress> addresses;
    /// Message object model
    LdnsPktPtr pkt;
};

struct Request {
    /// Query type
    RecordType type;
    /// A domain name to resolve
    std::string_view name;
};

struct EncodedRequest {
    /// Generated ID for the request
    uint16_t id;
    /// Raw DNS query
    std::vector<uint8_t> data;
};

struct Error {
    std::string description;
};

using DecodeResult = std::variant<DecodedRequest, DecodedReply, InapplicablePacket, Error>;
using EncodeResult = std::variant<EncodedRequest, Error>;

/**
 * Parse plain DNS packet(s)
 * @param packet encoded DNS packet(s)
 * @return answers if it's successfully decoded
 */
DecodeResult decode_packet(U8View packet);

/**
 * Make raw DNS request
 * @param request the DNS request to encode
 * @return non-nullopt if it's successfully encoded
 */
EncodeResult encode_request(const Request &request);

/** Convert DNS message from wire format to an object model. Return nullptr on error. */
LdnsPktPtr decode_pkt(U8View message);

/** Convert DNS message from an object model to wire format. Return nullptr on error. */
LdnsBufferPtr encode_pkt(const ldns_pkt *pkt);

/** Remove the "ech" parameter from the SvcParams part of any SVCB/HTTPS record contained in `pkt`. */
bool remove_svcparam_echconfig(ldns_pkt *pkt);

} // namespace dns_utils
} // namespace ag
