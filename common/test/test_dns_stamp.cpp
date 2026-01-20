#include <gtest/gtest.h>

#include "vpn/utils.h"

using namespace ag;

TEST(VpnDnsStampTest, DnsStampManipulationWorks) {
    const char *error = nullptr;
    VpnDnsStamp *stamp = vpn_dns_stamp_from_str("asdfasdfasdfsdf", &error);
    ASSERT_FALSE(stamp);
    ASSERT_TRUE(error);

    vpn_string_free(error);

    error = nullptr;
    const char *doh_str = "sdns://AgMAAAAAAAAADDk0LjE0MC4xNC4xNITK_rq-BN6tvu8PZG5zLmFkZ3VhcmQuY29tCi9kbnMtcXVlcnk";
    stamp = vpn_dns_stamp_from_str(doh_str, &error);
    ASSERT_TRUE(stamp);
    ASSERT_FALSE(error);
    ASSERT_STREQ(stamp->provider_name, "dns.adguard.com");
    ASSERT_STREQ(stamp->path, "/dns-query");
    ASSERT_TRUE(stamp->properties);
    ASSERT_TRUE(*stamp->properties & VDSIP_DNSSEC);
    ASSERT_TRUE(*stamp->properties & VDSIP_NO_LOG);
    ASSERT_FALSE(*stamp->properties & VDSIP_NO_FILTER);
    ASSERT_EQ(stamp->hashes.size, 2);

    using StrPtr = DeclPtr<const char, &vpn_string_free>;

    ASSERT_STREQ(StrPtr(vpn_dns_stamp_pretty_url(stamp)).get(), "https://dns.adguard.com/dns-query");
    ASSERT_STREQ(StrPtr(vpn_dns_stamp_prettier_url(stamp)).get(), "https://dns.adguard.com/dns-query");
    ASSERT_STREQ(StrPtr(vpn_dns_stamp_to_str(stamp)).get(), doh_str);

    VpnDnsStamp orig_stamp = *stamp;

    static uint8_t BYTES[] = "\xca\xfe\xba\xbe\xde\xad\xbe\xef";
    VpnBuffer hash = {.data = BYTES, .size = 4};
    stamp->proto = VDSP_DOQ;
    stamp->hashes.data = &hash;
    stamp->hashes.size = 1;
    *stamp->properties = VDSIP_NO_FILTER;
    stamp->path = nullptr;

    ASSERT_STREQ(StrPtr(vpn_dns_stamp_pretty_url(stamp)).get(), "quic://dns.adguard.com");
    ASSERT_STREQ(StrPtr(vpn_dns_stamp_prettier_url(stamp)).get(), "quic://dns.adguard.com");
    ASSERT_STREQ(StrPtr(vpn_dns_stamp_to_str(stamp)).get(),
            "sdns://BAQAAAAAAAAADDk0LjE0MC4xNC4xNATK_rq-D2Rucy5hZGd1YXJkLmNvbQ");

    stamp->proto = VDSP_DNSCRYPT;
    stamp->hashes.size = 0;
    stamp->provider_name = "2.dnscrypt-cert.adguard";
    stamp->server_public_key.data = BYTES;
    stamp->server_public_key.size = 8;

    ASSERT_STREQ(StrPtr(vpn_dns_stamp_pretty_url(stamp)).get(),
            "sdns://AQQAAAAAAAAADDk0LjE0MC4xNC4xNAjK_rq-3q2-7xcyLmRuc2NyeXB0LWNlcnQuYWRndWFyZA");
    ASSERT_STREQ(StrPtr(vpn_dns_stamp_prettier_url(stamp)).get(), "dnscrypt://2.dnscrypt-cert.adguard");
    ASSERT_STREQ(StrPtr(vpn_dns_stamp_to_str(stamp)).get(),
            "sdns://AQQAAAAAAAAADDk0LjE0MC4xNC4xNAjK_rq-3q2-7xcyLmRuc2NyeXB0LWNlcnQuYWRndWFyZA");

    *stamp = orig_stamp;
    vpn_dns_stamp_free(stamp);
}
