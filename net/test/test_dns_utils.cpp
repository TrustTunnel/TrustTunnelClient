#include <algorithm>

#include <gtest/gtest.h>

#include "net/dns_utils.h"

using namespace ag;

TEST(DNSUtilsDecode, A) {
    static constexpr uint8_t RESPONSE[] = {0xc5, 0x37, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x20, 0x6c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22, 0x00, 0x00, 0x29, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    dns_utils::DecodeResult result = dns_utils::decode_packet({RESPONSE, std::size(RESPONSE)});
    ASSERT_FALSE(std::holds_alternative<dns_utils::Error>(result)) << std::get<dns_utils::Error>(result).description;

    const auto &reply = std::get<dns_utils::DecodedReply>(result);
    ASSERT_EQ(reply.id, 0xc537);
    ASSERT_EQ(reply.question_type, dns_utils::RT_A);
    ASSERT_EQ(reply.names.size(), 1);
    ASSERT_EQ(reply.names[0], "example.com");
    ASSERT_EQ(reply.addresses.size(), 1);
    sockaddr_storage ip = sockaddr_from_raw(reply.addresses[0].ip.data(), reply.addresses[0].ip.size(), 0);
    ASSERT_EQ(sockaddr_to_str((sockaddr *) &ip), "93.184.216.34:0");
    ASSERT_EQ(reply.addresses[0].ttl, std::chrono::seconds(8300));
}

TEST(DNSUtilsDecode, AAAA) {
    static constexpr uint8_t RESPONSE[] = {0x9e, 0xd4, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x23, 0x6e, 0x00, 0x10, 0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
            0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00};

    dns_utils::DecodeResult result = dns_utils::decode_packet({RESPONSE, std::size(RESPONSE)});
    ASSERT_FALSE(std::holds_alternative<dns_utils::Error>(result)) << std::get<dns_utils::Error>(result).description;

    const auto &reply = std::get<dns_utils::DecodedReply>(result);
    ASSERT_EQ(reply.id, 0x9ed4);
    ASSERT_EQ(reply.question_type, dns_utils::RT_AAAA);
    ASSERT_EQ(reply.names.size(), 1);
    ASSERT_EQ(reply.names[0], "example.com");
    ASSERT_EQ(reply.addresses.size(), 1);
    sockaddr_storage ip = sockaddr_from_raw(reply.addresses[0].ip.data(), reply.addresses[0].ip.size(), 0);
    ASSERT_EQ(sockaddr_to_str((sockaddr *) &ip), "[2606:2800:220:1:248:1893:25c8:1946]:0");
    ASSERT_EQ(reply.addresses[0].ttl, std::chrono::seconds(9070));
}

TEST(DNSUtilsDecode, NXDomain) {
    static constexpr uint8_t RESPONSE[] = {0x06, 0x1d, 0x81, 0xa3, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x0b,
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x06, 0x00, 0x01, 0x00, 0x01, 0x51, 0x7c, 0x00, 0x40, 0x01, 0x61, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73,
            0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c,
            0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2d, 0x67, 0x72, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x78,
            0x77, 0x42, 0xc8, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x03, 0x84, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01, 0x51,
            0x80, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    dns_utils::DecodeResult result = dns_utils::decode_packet({RESPONSE, std::size(RESPONSE)});
    ASSERT_TRUE(std::holds_alternative<dns_utils::InapplicablePacket>(result)) << result.index();

    const auto &reply = std::get<dns_utils::InapplicablePacket>(result);
    ASSERT_EQ(reply.id, 0x061d);
}

TEST(DNSUtilsDecode, Cname) {
    static constexpr uint8_t RESPONSE[] = {0x96, 0xf0, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x03,
            0x77, 0x77, 0x77, 0x04, 0x68, 0x61, 0x62, 0x72, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
            0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xfd, 0x00, 0x02, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x0d, 0xfd, 0x00, 0x04, 0xb2, 0xf8, 0xed, 0x44, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00};

    dns_utils::DecodeResult result = dns_utils::decode_packet({RESPONSE, std::size(RESPONSE)});
    ASSERT_FALSE(std::holds_alternative<dns_utils::Error>(result)) << std::get<dns_utils::Error>(result).description;

    const auto &reply = std::get<dns_utils::DecodedReply>(result);
    ASSERT_EQ(reply.names.size(), 2);
    ASSERT_NE(std::find(reply.names.begin(), reply.names.end(), "habr.com"), reply.names.end());
    ASSERT_NE(std::find(reply.names.begin(), reply.names.end(), "www.habr.com"), reply.names.end());
    ASSERT_EQ(reply.addresses.size(), 1);
    sockaddr_storage ip = sockaddr_from_raw(reply.addresses[0].ip.data(), reply.addresses[0].ip.size(), 0);
    ASSERT_EQ(sockaddr_to_str((sockaddr *) &ip), "178.248.237.68:0");
    ASSERT_EQ(reply.addresses[0].ttl, std::chrono::seconds(3581));
}

TEST(DNSUtilsDecode, MultipleAddresses) {
    static constexpr uint8_t RESPONSE[] = {0xfb, 0x3c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x07,
            0x61, 0x64, 0x67, 0x75, 0x61, 0x72, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2b, 0x00, 0x04, 0x68, 0x14, 0x5b, 0x31, 0xc0, 0x0c, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x01, 0x2b, 0x00, 0x04, 0xac, 0x43, 0x03, 0x9d, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x01, 0x2b, 0x00, 0x04, 0x68, 0x14, 0x5a, 0x31, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00};

    dns_utils::DecodeResult result = dns_utils::decode_packet({RESPONSE, std::size(RESPONSE)});
    ASSERT_FALSE(std::holds_alternative<dns_utils::Error>(result)) << std::get<dns_utils::Error>(result).description;

    const auto &reply = std::get<dns_utils::DecodedReply>(result);
    ASSERT_EQ(reply.names.size(), 1);
    ASSERT_EQ(reply.names[0], "adguard.com");

    static const std::string ADDRESSES[] = {"104.20.91.49:0", "172.67.3.157:0", "104.20.90.49:0"};
    ASSERT_EQ(reply.addresses.size(), std::size(ADDRESSES));

    std::map<std::string, std::chrono::seconds> decoded_addresses;
    std::transform(reply.addresses.begin(), reply.addresses.end(),
            std::inserter(decoded_addresses, decoded_addresses.begin()), [](const dns_utils::AnswerAddress &a) {
                sockaddr_storage ip = sockaddr_from_raw(a.ip.data(), a.ip.size(), 0);
                return std::make_pair(sockaddr_to_str((sockaddr *) &ip), a.ttl);
            });

    for (const std::string &addr : ADDRESSES) {
        auto it = decoded_addresses.find(addr);
        ASSERT_NE(it, decoded_addresses.end()) << addr;
        ASSERT_EQ(it->second, std::chrono::seconds(299));
    }
}

TEST(DNSUtilsDecode, InvalidRDLENGTH) {
    // Header (12) + Question (7) + start of Answer (12) = 31 bytes
    static constexpr uint8_t BAD_RESPONSE[] = {
            // DNS header
            0x12, 0x34,                   // ID
            0x81, 0x80,                   // QR=1, RD/RA=1, RCODE=0
            0x00, 0x01,                   // QDCOUNT = 1
            0x00, 0x01,                   // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00,       // NSCOUNT, ARCOUNT
            // Question: "a." A IN=
            0x01, 0x61, 0x00,             // QNAME = "a."
            0x00, 0x01,                   // QTYPE = A
            0x00, 0x01,                   // QCLASS = IN
            // Answer (truncated)=
            0xC0, 0x0C,                   // NAME = ptr to QNAME
            0x00, 0x05,                   // TYPE = CNAME
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL  = 60
            0x00, 0x03                    // **RDLENGTH = 3, but 0 bytes follow → mismatch**
    };

    dns_utils::DecodeResult result = dns_utils::decode_packet({BAD_RESPONSE, std::size(BAD_RESPONSE)});
    ASSERT_TRUE(std::holds_alternative<dns_utils::Error>(result));
}

TEST(DNSUtilsDecode, InvalidOwnerNamePointer) {
    static constexpr uint8_t BAD_RESPONSE[] = {
            // DNS Header
            0x12, 0x34,                   // ID
            0x81, 0x80,                   // QR=1 (response), RCODE=0
            0x00, 0x01,                   // QDCOUNT = 1
            0x00, 0x01,                   // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00,       // NSCOUNT, ARCOUNT = 0
            // Question: "a." A IN
            0x01, 0x61, 0x00,             // QNAME = "a."
            0x00, 0x01,                   // QTYPE = A
            0x00, 0x01,                   // QCLASS = IN
            // Answer: NAME = invalid pointer (C0 FF → offset 0xFF, outside the package)
            0xC0, 0xFF,                   // NAME = pointer to 0xFF -> error
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x04,                   // RDLENGTH = 4
            0x7F, 0x00, 0x00, 0x01        // RDATA = 127.0.0.1
    };

    dns_utils::DecodeResult result = dns_utils::decode_packet({BAD_RESPONSE, std::size(BAD_RESPONSE)});
    ASSERT_TRUE(std::holds_alternative<dns_utils::Error>(result));
}

TEST(DNSUtilsDecode, DnsResponseWithRdataEmpty) {
    static constexpr uint8_t BAD_RESPONSE[] = {
            // DNS-header
            0x12,0x34,             // ID
            0x81,0x80,             // QR=1, RD/RA=1, RCODE=0
            0x00,0x01,             // QDCOUNT = 1
            0x00,0x01,             // ANCOUNT = 1
            0x00,0x00,             // NSCOUNT = 0
            0x00,0x00,             // ARCOUNT = 0
            // Question: “a.” A IN
            0x01,0x61,0x00,        // QNAME = "a."
            0x00,0x01,             // QTYPE = A
            0x00,0x01,             // QCLASS = IN
            // Answer: CNAME with empty RDLENGTH
            0xC0,0x0C,             // NAME = pointer to QNAME (offset 12)
            0x00,0x05,             // TYPE = CNAME
            0x00,0x01,             // CLASS = IN
            0x00,0x00,0x00,0x3C,   // TTL  = 60
            0x00,0x00              // **RDLENGTH = 0 -> no RDATA**
    };

    dns_utils::DecodeResult result = dns_utils::decode_packet({BAD_RESPONSE, std::size(BAD_RESPONSE)});
    ASSERT_FALSE(std::holds_alternative<dns_utils::Error>(result)) << std::get<dns_utils::Error>(result).description;
}

TEST(DNSUtilsEncode, A) {
    static constexpr uint8_t EXPECTED[] = {0x2a, 0x18, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};

    dns_utils::EncodeResult result = dns_utils::encode_request({dns_utils::RT_A, "example.com"});
    ASSERT_FALSE(std::holds_alternative<dns_utils::Error>(result)) << std::get<dns_utils::Error>(result).description;

    const auto &pkt = std::get<dns_utils::EncodedRequest>(result).data;
    ASSERT_EQ(pkt.size(), std::size(EXPECTED));
    ASSERT_EQ(0, memcmp(pkt.data() + 2, EXPECTED + 2, pkt.size() - 2)); // don't check ID
}

TEST(DNSUtilsEncode, AAAA) {
    static constexpr uint8_t EXPECTED[] = {0xfc, 0xba, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01};

    dns_utils::EncodeResult result = dns_utils::encode_request({dns_utils::RT_AAAA, "example.com"});
    ASSERT_FALSE(std::holds_alternative<dns_utils::Error>(result)) << std::get<dns_utils::Error>(result).description;

    const auto &pkt = std::get<dns_utils::EncodedRequest>(result).data;
    ASSERT_EQ(pkt.size(), std::size(EXPECTED));
    ASSERT_EQ(0, memcmp(pkt.data() + 2, EXPECTED + 2, pkt.size() - 2)); // don't check ID
}
