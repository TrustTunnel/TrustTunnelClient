#include <gtest/gtest.h>

#include <string>

#include "trusttunnel/trusttunnel_deeplink.h"

namespace {

// The `tt://` URI produced for a known endpoint configuration; the same one the Android
// adapter's DeepLinkInstrumentedTest asserts on. Split across string literals only to keep
// the lines within the column limit.
constexpr const char *KNOWN_URI =
        "tt://"
        "AQlsb2NhbGhvc3QFBHRlc3QGBHRlc3QCDjEyNy4wLjAuMTo0NDQzCwRhYWJiAwlsb2NhbGhvc3QIQVMwggFPMIH1oAMCAQICFGi8WMY2yFmt"
        "W2u_"
        "18hMQBa0T4VGMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjAxMzAwMDAwMDBaFw0yNzAxMzAwMDAwMDBaMBQxEjAQBg"
        "NVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB4ozK9KbqScCCTJ8CvTfW4W0r9OEsn4VcQswd-BbP9z-"
        "tdyfE5HT4uHLUSZ"
        "RWUKfZjnRRkHWOwhp9KJhOE-"
        "LAWjJTAjMCEGA1UdEQQaMBiCCWxvY2FsaG9zdIILKi5sb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAO6gFBHDsg"
        "vWjPj39JNchcMF3X2ICgzycBwTyydxqpdiAiEAgybYwECuZopK1g6JX5tK0-5B3Of7n0NuPXRGSU5TtSc";

constexpr const char *ENDPOINT_TOML = "[endpoint]\n"
                                      "hostname = \"localhost\"\n"
                                      "addresses = [\"127.0.0.1:4443\"]\n"
                                      "username = \"test\"\n"
                                      "password = \"test\"\n"
                                      "client_random = \"aabb\"\n"
                                      "custom_sni = \"localhost\"\n"
                                      "name = \"Example VPN\"\n"
                                      "dns_upstreams = [\"tls://dns.adguard-dns.com\"]\n";

// Assert that the decoded TOML contains the fields of the endpoint behind KNOWN_URI.
void expect_known_endpoint(const std::string &config) {
    EXPECT_NE(config.find("hostname = \"localhost\""), std::string::npos);
    EXPECT_NE(config.find("username = \"test\""), std::string::npos);
    EXPECT_NE(config.find("password = \"test\""), std::string::npos);
    EXPECT_NE(config.find("client_random = \"aabb\""), std::string::npos);
    EXPECT_NE(config.find("upstream_protocol = \"http2\""), std::string::npos);
    EXPECT_NE(config.find("custom_sni = \"localhost\""), std::string::npos);
    EXPECT_NE(config.find("addresses = [\"127.0.0.1:4443\"]"), std::string::npos);
}

TEST(DeepLink, DecodeKnownUri) {
    char *result = trusttunnel_decode_deeplink(KNOWN_URI);
    ASSERT_NE(result, nullptr);

    std::string config{result};
    trusttunnel_free_deeplink_string(result);

    EXPECT_NE(config.find("[endpoint]"), std::string::npos);
    EXPECT_NE(config.find("-----BEGIN CERTIFICATE-----"), std::string::npos);
    expect_known_endpoint(config);
}

TEST(DeepLink, EncodeThenDecode) {
    char *result = trusttunnel_encode_deeplink(ENDPOINT_TOML);
    ASSERT_NE(result, nullptr);

    std::string uri{result};
    trusttunnel_free_deeplink_string(result);

    EXPECT_TRUE(uri.rfind("tt://", 0) == 0);

    result = trusttunnel_decode_deeplink(uri.c_str());
    ASSERT_NE(result, nullptr);

    std::string config{result};
    trusttunnel_free_deeplink_string(result);

    expect_known_endpoint(config);
    EXPECT_NE(config.find("name = \"Example VPN\""), std::string::npos);
    EXPECT_NE(config.find("tls://dns.adguard-dns.com"), std::string::npos);
}

TEST(DeepLink, EncodeDecodeRoundtrip) {
    char *decoded = trusttunnel_decode_deeplink(KNOWN_URI);
    ASSERT_NE(decoded, nullptr);

    char *uri = trusttunnel_encode_deeplink(decoded);
    trusttunnel_free_deeplink_string(decoded);
    ASSERT_NE(uri, nullptr);

    std::string uri_str{uri};
    trusttunnel_free_deeplink_string(uri);

    EXPECT_TRUE(uri_str.rfind("tt://", 0) == 0);

    char *result = trusttunnel_decode_deeplink(uri_str.c_str());
    ASSERT_NE(result, nullptr);

    std::string config{result};
    trusttunnel_free_deeplink_string(result);

    expect_known_endpoint(config);
}

TEST(DeepLink, EncodeRejectsInvalidToml) {
    EXPECT_EQ(trusttunnel_encode_deeplink("not a valid toml"), nullptr);
}

TEST(DeepLink, EncodeRejectsMissingEndpointTable) {
    EXPECT_EQ(trusttunnel_encode_deeplink("hostname = \"vpn.example.com\""), nullptr);
}

TEST(DeepLink, DecodeRejectsUnknownScheme) {
    EXPECT_EQ(trusttunnel_decode_deeplink("http://example.com"), nullptr);
}

TEST(DeepLink, NullArgumentsAreSafe) {
    EXPECT_EQ(trusttunnel_decode_deeplink(nullptr), nullptr);
    EXPECT_EQ(trusttunnel_encode_deeplink(nullptr), nullptr);

    // Freeing NULL must be a no-op, not a crash.
    trusttunnel_free_deeplink_string(nullptr);
}

} // namespace
