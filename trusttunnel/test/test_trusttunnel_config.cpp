#include <string>
#include <string_view>

#include <gtest/gtest.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "vpn/trusttunnel/config.h"
#include "vpn/utils.h"

using namespace ag;

// Test CA certificate (CN=TrustTunnel Test CA), not present in the system trust store.
// Valid until 2126 so that the tests don't start failing on expiration.
static constexpr std::string_view TEST_CA_PEM = R"(-----BEGIN CERTIFICATE-----
MIIDDjCCAfagAwIBAgIUDInSR3zpQfI4IB9cxSRmAgGcn38wDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTVHJ1c3RUdW5uZWwgVGVzdCBDQTAgFw0yNjEwMDgxOTE2
NTZaGA8yMTI2MDkxNDE5MTY1NlowHjEcMBoGA1UEAwwTVHJ1c3RUdW5uZWwgVGVz
dCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIod7DFeOd34kNpQ
kh8hCJengRHwS6a+bcPD2zNB68pCi2Ym8a8c7pNTpc8ApowSiMYsHTknKDFl5aS+
8THgHleHkIIe2+L435uevRCEo9fScL6j51u4B+FCbQ/YMcuz8cJ9IvedxYagjYSg
BGx41MkWWi+yq+tACnOeHyJiLj8AR9K9Z5wXF60RI9SKW5bh/QVOVn8XrNkyhF14
mYJ6N6N7y5vc3C1PDJk/PHzemPulez+HHVn4ZfmGRTCzBgzc11CSlUqQpi16E3QO
agJYCJjirIzFM7QZfSCi8Og9F9rmHkyJmvuNKvsqQaLkJmuHnO1Bgi8arl2fTA39
BuwZ/NsCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
HQYDVR0OBBYEFCkkJ/NA6YEk6oXEENngpEdS5Fa0MA0GCSqGSIb3DQEBCwUAA4IB
AQATLtfR2iW/yRqKirCfPoHrf3GmqeaNKTsobauOfktOHK3HmTGRnn6PX8Wb/8fB
wyfnB0v7xWAXDVEiRvsI9CJpLQCKPWdUMxIrzL3gexMz4/Yme9/3Cc168RX23aLD
aFlUB8LqAleLaddLvuGe2sB9DNKRBxh1XoDSmHyeW+M2fho+ifRDe5AL7OQ49F8P
Y8V1Y7zOtbq3c/uyhKJh2nK83Tq6NjllPw2S1RAMxfaQ9v7VCxtwAboIbNZB1X+Y
QB8nYXgEGrIEpjxj/V0Z9z3Sn+DSJh+uC5QUCE/NSnGtIA8gydt/NBC3bwv5O/Tc
Lwp9InBotNsaCo59sszZ5l/v
-----END CERTIFICATE-----
)";

// Leaf certificate (CN=vpn.example.com, SAN=DNS:vpn.example.com) signed by `TEST_CA_PEM`.
// Valid until 2126 so that the tests don't start failing on expiration.
static constexpr std::string_view TEST_LEAF_PEM = R"(-----BEGIN CERTIFICATE-----
MIIDWzCCAkOgAwIBAgIURsL6Yg3mX99tqM7q5Xe08HTYbZgwDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTVHJ1c3RUdW5uZWwgVGVzdCBDQTAgFw0yNjEwMDgxOTE2
NTdaGA8yMTI2MDkxNDE5MTY1N1owGjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqjfLXJSLDZ415LOrPV5S
WlmX3tNKaoPVkgDG/XEtbDr0Vh31tYZdeH1pKJ34HgxMvJbmuVPBNuIltm8HCeSa
4E+5/EcEV5c2yXfycAPGRy4SqT6XzphZhZWBuo86hJEU04/PvdnbZAaB24MXP1KH
jm8l/Pxkg6byrezfXPNHX3uU+y0n7LvVMEFxIqiXsax61osrFG97u2+xOCj2yHve
ZST46rDzGRIty4u8LkCxxvVWhmAgMbCs6F5B4P0DMbSeBoRR9YozqMY/hC/bNfbI
emoaY9RXHcJ7IlhMqu6o6kOg3qTxP6+yxNzKLEg1pfAkxfEAmU5SEOXHsYatOjI5
vwIDAQABo4GSMIGPMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMBoGA1UdEQQTMBGCD3Zwbi5leGFtcGxlLmNvbTAdBgNV
HQ4EFgQUykdNE3cZHKVHH5n5QaJewrLRT88wHwYDVR0jBBgwFoAUKSQn80DpgSTq
hcQQ2eCkR1LkVrQwDQYJKoZIhvcNAQELBQADggEBAAdp2+xV7TlHmg16kDRC2bgt
y9GDtJ32pmV+UpXlQcdGj6ktkenl8PFm8ERpzk/bn9IyHz1vlXvpLH+gaXp4JH9t
LpsLDkuzP6zD8f1QB5MtrH98R6o+nGfPr4/qqG3f8ZIJyDE/KvogPKW2S5RxnJiI
AYOEvXEeis3V7y/2y1/47rvDItqDUNfenQO3FpE4/b+2jpRE7hQGDTLysqgLzzL2
JK0JgYgL56Os+cw+nTMqH7bpYIbbgvsDrnhk4tVoYxQlH8lle4L4zitOkrOnHTff
O3usQjKGgl8ueYKOTYQrkl6Wsz6/tNRkKljww9R9kYEm2mQajDGgAjOdANJaY8E=
-----END CERTIFICATE-----
)";

/// Build a trust store containing the test CA, to stand in for the system one.
static UniquePtr<X509_STORE, &X509_STORE_free> make_test_ca_store() {
    UniquePtr<BIO, &BIO_free> bio{BIO_new_mem_buf(TEST_CA_PEM.data(), static_cast<int>(TEST_CA_PEM.size()))};
    UniquePtr<X509, &X509_free> ca{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
    UniquePtr<X509_STORE, &X509_STORE_free> store{X509_STORE_new()};
    EXPECT_NE(ca.get(), nullptr);
    EXPECT_EQ(X509_STORE_add_cert(store.get(), ca.get()), 1);
    return store;
}

TEST(TrustTunnelConfigTest, ChainIsVerifiableWithMatchingTrustStore) {
    auto store = make_test_ca_store();
    std::string chain = std::string(TEST_LEAF_PEM).append(TEST_CA_PEM);
    EXPECT_TRUE(TrustTunnelConfig::is_certificate_system_verifiable(chain, "vpn.example.com", store.get()));
}

TEST(TrustTunnelConfigTest, LeafOnlyIsVerifiableWithMatchingTrustStore) {
    auto store = make_test_ca_store();
    EXPECT_TRUE(TrustTunnelConfig::is_certificate_system_verifiable(TEST_LEAF_PEM, "vpn.example.com", store.get()));
}

TEST(TrustTunnelConfigTest, VerifiableChainWithWrongHostnameIsNotVerifiable) {
    auto store = make_test_ca_store();
    EXPECT_FALSE(TrustTunnelConfig::is_certificate_system_verifiable(TEST_LEAF_PEM, "other.example.com", store.get()));
}

TEST(TrustTunnelConfigTest, PipeHostnameIsVerifiedAgainstRemoteIdPart) {
    auto store = make_test_ca_store();
    // The part after the pipe is the one the certificate is verified against at connect time.
    EXPECT_TRUE(TrustTunnelConfig::is_certificate_system_verifiable(
            TEST_LEAF_PEM, "sni.example.org|vpn.example.com", store.get()));
    EXPECT_FALSE(TrustTunnelConfig::is_certificate_system_verifiable(
            TEST_LEAF_PEM, "vpn.example.com|sni.example.org", store.get()));
}

TEST(TrustTunnelConfigTest, EmptyHostnameIsNotVerifiable) {
    auto store = make_test_ca_store();
    EXPECT_FALSE(TrustTunnelConfig::is_certificate_system_verifiable(TEST_LEAF_PEM, "", store.get()));
}

TEST(TrustTunnelConfigTest, ChainIsNotVerifiableWithEmptyTrustStore) {
    UniquePtr<X509_STORE, &X509_STORE_free> store{X509_STORE_new()};
    std::string chain = std::string(TEST_LEAF_PEM).append(TEST_CA_PEM);
    EXPECT_FALSE(TrustTunnelConfig::is_certificate_system_verifiable(chain, "vpn.example.com", store.get()));
}

TEST(TrustTunnelConfigTest, SelfSignedChainIsNotSystemVerifiable) {
    std::string chain = std::string(TEST_LEAF_PEM).append(TEST_CA_PEM);
    EXPECT_FALSE(TrustTunnelConfig::is_certificate_system_verifiable(chain, "vpn.example.com"));
}

TEST(TrustTunnelConfigTest, EmptyPemIsNotSystemVerifiable) {
    EXPECT_FALSE(TrustTunnelConfig::is_certificate_system_verifiable("", "vpn.example.com"));
}

TEST(TrustTunnelConfigTest, InvalidPemIsNotSystemVerifiable) {
    EXPECT_FALSE(TrustTunnelConfig::is_certificate_system_verifiable("not a certificate", "vpn.example.com"));
}

/// Parse `config` and build the deep-link export table out of it, with the test CA trusted.
static std::optional<toml::table> export_table(
        std::string_view config, X509_STORE *store = nullptr, std::string_view name = {}) {
    toml::parse_result parsed = toml::parse(config);
    EXPECT_TRUE(parsed) << "the test configuration must be valid TOML";
    if (!parsed) {
        return std::nullopt;
    }
    return TrustTunnelConfig::build_deeplink_export_table(parsed.table(), name, store);
}

static constexpr std::string_view MINIMAL_CONFIG = R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
)";

TEST(TrustTunnelExportTest, MinimalConfigIsExported) {
    std::optional result = export_table(MINIMAL_CONFIG);
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["hostname"].value_or(std::string{}), "vpn.example.com");
    EXPECT_EQ((*endpoint)["username"].value_or(std::string{}), "alice");
    EXPECT_EQ((*endpoint)["password"].value_or(std::string{}), "s3cr3t");
}

TEST(TrustTunnelExportTest, NameAndDnsUpstreamsArePreserved) {
    std::optional result = export_table(R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
name = "Example VPN"
dns_upstreams = ["tls://dns.adguard-dns.com"]
)");
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["name"].value_or(std::string{}), "Example VPN");
    const toml::array *dns_upstreams = (*endpoint)["dns_upstreams"].as_array();
    ASSERT_NE(dns_upstreams, nullptr);
    ASSERT_EQ(dns_upstreams->size(), 1);
    EXPECT_EQ(dns_upstreams->get(0)->value_or(std::string{}), "tls://dns.adguard-dns.com");
}

TEST(TrustTunnelExportTest, NameFromConfigIsKeptWithoutOverride) {
    std::optional result = export_table(R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
name = "From Config"
)");
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["name"].value_or(std::string{}), "From Config");
}

TEST(TrustTunnelExportTest, NameOverrideReplacesConfigName) {
    std::optional result = export_table(R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
name = "From Config"
)",
            nullptr, "From Command Line");
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["name"].value_or(std::string{}), "From Command Line");
}

TEST(TrustTunnelExportTest, NameOverrideIsOptional) {
    std::optional result = export_table(MINIMAL_CONFIG);
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["name"].value_or(std::string{}), "");
}

TEST(TrustTunnelExportTest, MissingEndpointTableIsRejected) {
    EXPECT_FALSE(export_table("loglevel = \"info\"").has_value());
    // An array of tables is not the layout the client supports.
    EXPECT_FALSE(export_table("[[endpoint]]\nhostname = \"vpn.example.com\"").has_value());
}

TEST(TrustTunnelExportTest, MissingHostnameIsRejected) {
    static constexpr std::string_view CONFIG = R"(
[endpoint]
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
)";
    EXPECT_FALSE(export_table(CONFIG).has_value());
}

TEST(TrustTunnelExportTest, MissingAddressesAreRejected) {
    static constexpr std::string_view CONFIG = R"(
[endpoint]
hostname = "vpn.example.com"
username = "alice"
password = "s3cr3t"
)";
    EXPECT_FALSE(export_table(CONFIG).has_value());
}

TEST(TrustTunnelExportTest, AllEmptyAddressesAreRejected) {
    static constexpr std::string_view CONFIG = R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["", ""]
username = "alice"
password = "s3cr3t"
)";
    EXPECT_FALSE(export_table(CONFIG).has_value());
}

TEST(TrustTunnelExportTest, EmptyAddressAndDnsUpstreamEntriesAreDropped) {
    std::optional result = export_table(R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["", "1.2.3.4:443", ""]
username = "alice"
password = "s3cr3t"
dns_upstreams = ["", "tls://dns.adguard-dns.com", ""]
)");
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);

    const toml::array *addresses = (*endpoint)["addresses"].as_array();
    ASSERT_NE(addresses, nullptr);
    ASSERT_EQ(addresses->size(), 1);
    EXPECT_EQ(addresses->get(0)->value_or(std::string{}), "1.2.3.4:443");

    const toml::array *dns_upstreams = (*endpoint)["dns_upstreams"].as_array();
    ASSERT_NE(dns_upstreams, nullptr);
    ASSERT_EQ(dns_upstreams->size(), 1);
    EXPECT_EQ(dns_upstreams->get(0)->value_or(std::string{}), "tls://dns.adguard-dns.com");
}

/// Render a configuration with the test leaf certificate and the given extra settings.
static std::string config_with_certificate(std::string_view extra) {
    return std::string(R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
)")
            .append(extra)
            .append("certificate = \"\"\"\n")
            .append(TEST_LEAF_PEM)
            .append("\"\"\"\n");
}

TEST(TrustTunnelExportTest, VerifiableCertificateIsOmitted) {
    auto store = make_test_ca_store();
    std::optional result = export_table(config_with_certificate(""), store.get());
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["certificate"].value_or(std::string{}), "");
}

TEST(TrustTunnelExportTest, UnverifiableCertificateIsKept) {
    UniquePtr<X509_STORE, &X509_STORE_free> store{X509_STORE_new()};
    std::optional result = export_table(config_with_certificate(""), store.get());
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["certificate"].value_or(std::string{}), TEST_LEAF_PEM);
}

TEST(TrustTunnelExportTest, CertificateIsKeptWhenVerificationIsSkipped) {
    // Importing clients may ignore `skip_verification`, so the certificate must survive:
    // it is the only way for them to accept a self-signed endpoint.
    UniquePtr<X509_STORE, &X509_STORE_free> store{X509_STORE_new()};
    std::optional result = export_table(config_with_certificate("skip_verification = true\n"), store.get());
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["certificate"].value_or(std::string{}), TEST_LEAF_PEM);
    EXPECT_TRUE((*endpoint)["skip_verification"].value_or(false));
}

TEST(TrustTunnelExportTest, PipeHostnameIsSplitIntoHostnameAndCustomSni) {
    auto store = make_test_ca_store();
    std::string config = R"(
[endpoint]
hostname = "sni.example.org|vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
certificate = """)";
    config.append("\n").append(TEST_LEAF_PEM).append("\"\"\"\n");

    std::optional result = export_table(config, store.get());
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    // `remote_id` becomes the hostname (it is what the certificate is verified against),
    // `sni` becomes the custom SNI.
    EXPECT_EQ((*endpoint)["hostname"].value_or(std::string{}), "vpn.example.com");
    EXPECT_EQ((*endpoint)["custom_sni"].value_or(std::string{}), "sni.example.org");
    EXPECT_EQ((*endpoint)["certificate"].value_or(std::string{}), "");
}

TEST(TrustTunnelExportTest, PipeHostnameWithoutCustomSniPartUsesRemoteId) {
    std::optional result = export_table(R"(
[endpoint]
hostname = "vpn.example.com|"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
)");
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["hostname"].value_or(std::string{}), "vpn.example.com");
    EXPECT_EQ((*endpoint)["custom_sni"].value_or(std::string{}), "");
}

TEST(TrustTunnelExportTest, CustomSniWithPipeHostnameIsRejected) {
    std::optional result = export_table(R"(
[endpoint]
hostname = "sni.example.org|vpn.example.com"
custom_sni = "sni.example.org"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
)");
    EXPECT_FALSE(result.has_value());
}

TEST(TrustTunnelExportTest, ClientRandomMaskIsKeptInTheExportTable) {
    // The Rust settings mapping drops the mask when it encodes the deep-link; the export
    // table itself still carries the raw `prefix/mask` value.
    std::optional result = export_table(R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
client_random = "aabb/ccdd"
)");
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["client_random"].value_or(std::string{}), "aabb/ccdd");
}

TEST(TrustTunnelExportTest, ClientRandomAuthKeyIsKeptInTheExportTable) {
    std::optional result = export_table(R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
client_random_auth_key = "aabbccdd"
)");
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ((*endpoint)["client_random_auth_key"].value_or(std::string{}), "aabbccdd");
}

TEST(TrustTunnelExportTest, SubscriptionUrlIsKeptInTheExportTable) {
    std::optional result = export_table(R"(
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"

[endpoint.subscription]
url = "https://u:p@vpn.example.com/subscription"
)");
    ASSERT_TRUE(result.has_value());
    const toml::table *endpoint = (*result)["endpoint"].as_table();
    ASSERT_NE(endpoint, nullptr);
    const toml::table *subscription = (*endpoint)["subscription"].as_table();
    ASSERT_NE(subscription, nullptr);
    EXPECT_EQ((*subscription)["url"].value_or(std::string{}), "https://u:p@vpn.example.com/subscription");
}
