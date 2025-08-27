#include <gtest/gtest.h>

#include "vpn/internal/domain_filter.h"
#include "vpn/utils.h"

using namespace ag;

// Settings update should purge previous entries
TEST(MatchTest, UpdateSettings) {
    DomainFilter filter = {};
    ASSERT_TRUE(filter.update_exclusions(VPN_MODE_GENERAL, "example.com"));
    ASSERT_EQ(filter.match_domain("example.com"), DFMS_EXCLUSION);

    ASSERT_TRUE(filter.update_exclusions(VPN_MODE_GENERAL, ""));
    ASSERT_EQ(filter.match_domain("example.com"), DFMS_DEFAULT);
}

struct MatchTestParam {
    VpnMode mode;
    std::string_view exclusions;
    std::string entry;
};

class MatchTest : public testing::TestWithParam<MatchTestParam> {
public:
    DomainFilter filter = {};

    static void SetUpTestSuite() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    void SetUp() override {
        const MatchTestParam &param = GetParam();
        ASSERT_TRUE(filter.update_exclusions(param.mode, param.exclusions));
    }
};

class DomainMatch : public MatchTest {};
TEST_P(DomainMatch, Test) {
    const MatchTestParam &param = GetParam();
    ASSERT_EQ(DFMS_EXCLUSION, filter.match_domain(param.entry));
}

static const MatchTestParam DOMAIN_MATCH_TEST_SAMPLES[] = {
        {VPN_MODE_GENERAL, "example.com", "example.com"},
        {VPN_MODE_GENERAL, "example.com    example.org", "example.com"},
        {VPN_MODE_GENERAL, "example.com example.org", "example.org"},

        {VPN_MODE_GENERAL, "example.com", "www.example.com"},
        {VPN_MODE_GENERAL, "www.example.com", "example.com"},

        {VPN_MODE_GENERAL, "*.example.com", "sub.example.com"},
        {VPN_MODE_GENERAL, "*.example.com", "www.example.com"},

        {VPN_MODE_GENERAL, "example.com *.example.com", "sub.example.com"},
        {VPN_MODE_GENERAL, "*.example.com example.com", "example.com"},
        {VPN_MODE_GENERAL, "*.example.com", "*.example.com"},
};
INSTANTIATE_TEST_SUITE_P(Simple, DomainMatch, testing::ValuesIn(DOMAIN_MATCH_TEST_SAMPLES));

class DomainNoMatch : public MatchTest {};
TEST_P(DomainNoMatch, Test) {
    const MatchTestParam &param = GetParam();
    ASSERT_EQ(DFMS_DEFAULT, filter.match_domain(param.entry));
}

static const MatchTestParam DOMAIN_NOMATCH_TEST_SAMPLES[] = {
        {VPN_MODE_GENERAL, "example.com", "example.org"},
        {VPN_MODE_GENERAL, "example.com example.org", "example.net"},

        {VPN_MODE_GENERAL, "sub.example.com", "example.com"},
        {VPN_MODE_GENERAL, "example.com", "sub.sub.example.com"},
        {VPN_MODE_GENERAL, "example.com", "www.example.org"},
        {VPN_MODE_GENERAL, "example.com", "sub.example.org"},
        {VPN_MODE_GENERAL, "example.com", "example.com."},
        {VPN_MODE_GENERAL, "example.com", "*.example.com"},
};
INSTANTIATE_TEST_SUITE_P(Simple, DomainNoMatch, testing::ValuesIn(DOMAIN_NOMATCH_TEST_SAMPLES));

class AddressMatch : public MatchTest {};
TEST_P(AddressMatch, Test) {
    const MatchTestParam &param = GetParam();

    SocketAddress address(param.entry.c_str());
    ASSERT_TRUE(address.valid());
    ASSERT_EQ(DFMS_EXCLUSION, filter.match_tag({address, ""}).status);
}

static const MatchTestParam ADDRESS_MATCH_TEST_SAMPLES[] = {
        {VPN_MODE_GENERAL, "1.1.1.1 2.2.2.2", "1.1.1.1"},
        {VPN_MODE_GENERAL, "1.1.1.1 2.2.2.2", "2.2.2.2"},
        {VPN_MODE_GENERAL, "dead::beef \t feed::babe", "dead::beef"},
        {VPN_MODE_GENERAL, "dead::beef feed::babe", "feed::babe"},
        {VPN_MODE_SELECTIVE, "1.1.1.1 2.2.2.2", "1.1.1.1"},
        {VPN_MODE_SELECTIVE, "dead::beef feed::babe", "feed::babe"},

        {VPN_MODE_GENERAL, "[dead::beef]", "[dead::beef]:1234"},
        {VPN_MODE_GENERAL, "dead::beef", "[dead::beef]:70"},
        {VPN_MODE_GENERAL, "1.1.1.1", "1.1.1.1:30"},
        {VPN_MODE_GENERAL, "1.1.1.1", "1.1.1.1:60"},

        {VPN_MODE_GENERAL, "192.168.0.0/16", "192.168.0.1"},
        {VPN_MODE_GENERAL, "192.168.0.0/16", "192.168.0.1:30"},
        {VPN_MODE_GENERAL, "2000::/64", "2000::1"},
        {VPN_MODE_GENERAL, "2000::/64", "[2000::1]"},
        {VPN_MODE_GENERAL, "2000::/64", "[2000::1]:123"},
};
INSTANTIATE_TEST_SUITE_P(Simple, AddressMatch, testing::ValuesIn(ADDRESS_MATCH_TEST_SAMPLES));

class AddressNoMatch : public MatchTest {};
TEST_P(AddressNoMatch, Test) {
    const MatchTestParam &param = GetParam();

    SocketAddress address(param.entry.c_str());
    ASSERT_TRUE(address.valid());
    ASSERT_EQ(filter.match_tag({address, ""}).status, DFMS_DEFAULT);
}

static const MatchTestParam ADDRESS_NOMATCH_TEST_SAMPLES[] = {
        {VPN_MODE_GENERAL, "1.1.1.1 2.2.2.2", "3.3.3.3"},
        {VPN_MODE_GENERAL, "dead::beef feed::babe", "beef::babe"},
        {VPN_MODE_SELECTIVE, "1.1.1.1 2.2.2.2", "3.3.3.3"},
        {VPN_MODE_SELECTIVE, "dead::beef feed::babe", "babe::beef"},

        {VPN_MODE_GENERAL, "1.1.1.1:1", "1.1.1.1:2"},
        {VPN_MODE_GENERAL, "[dead::beef]:1", "[dead::beef]:2"},

        {VPN_MODE_GENERAL, "192.168.0.0/16", "172.168.0.0"},
        {VPN_MODE_GENERAL, "192.168.0.0/16", "172.168.0.0:1122"},
        {VPN_MODE_GENERAL, "2000::/64", "2001::1"},
        {VPN_MODE_GENERAL, "2000::/64", "[2001::1]"},
        {VPN_MODE_GENERAL, "2000::/64", "[2001::1]:4433"},
};
INSTANTIATE_TEST_SUITE_P(Simple, AddressNoMatch, testing::ValuesIn(ADDRESS_NOMATCH_TEST_SAMPLES));

struct TagsTestParam {
    std::string address;
    std::string app;
};

class Tags : public testing::TestWithParam<TagsTestParam> {
public:
    DomainFilter filter = {};
    SocketAddress address = {};

    static void SetUpTestSuite() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    void SetUp() override {
        const TagsTestParam &param = GetParam();

        address = SocketAddress(param.address.c_str());
        ASSERT_TRUE(address.valid());

        ASSERT_TRUE(filter.update_exclusions(VPN_MODE_GENERAL, "example.com"));
    }
};

TEST_P(Tags, Basic) {
    const TagsTestParam &param = GetParam();

    ASSERT_EQ(filter.match_tag({address, param.app}).status, DFMS_DEFAULT);

    filter.add_resolved_tag({address, param.app}, "example.com");
    auto res = filter.match_tag({address, param.app});
    ASSERT_EQ(res.status, DFMS_EXCLUSION);
    ASSERT_EQ(res.domain, "example.com");
    res = filter.match_tag({address, ""});
    ASSERT_EQ(res.status, DFMS_DEFAULT);
    ASSERT_FALSE(res.domain.has_value());
    res = filter.match_tag({address, param.app + "1"});
    ASSERT_EQ(res.status, DFMS_DEFAULT);
    ASSERT_FALSE(res.domain.has_value());
}

static const TagsTestParam TAGS_TEST_SAMPLES[] = {
        {"1.1.1.1:1", "test"},
        {"[abcd::feed]:13", "test"},
};
INSTANTIATE_TEST_SUITE_P(Tags, Tags, testing::ValuesIn(TAGS_TEST_SAMPLES));

TEST(DomainFilterTest, ValidateEntry) {
    ASSERT_EQ(DFVS_OK_DOMAIN, DomainFilter::validate_entry("google.com"));
    ASSERT_EQ(DFVS_OK_DOMAIN, DomainFilter::validate_entry("google123.com"));
    ASSERT_EQ(DFVS_OK_DOMAIN, DomainFilter::validate_entry("gOOgle.com"));
    ASSERT_EQ(DFVS_OK_ADDR, DomainFilter::validate_entry("1.1.1.1:1"));
    ASSERT_EQ(DFVS_OK_ADDR, DomainFilter::validate_entry("1.2.3.4"));
    ASSERT_EQ(DFVS_OK_DOMAIN, DomainFilter::validate_entry("1.2.3.257"));
    ASSERT_EQ(DFVS_OK_DOMAIN, DomainFilter::validate_entry("1.2.3.4.5"));
    ASSERT_EQ(DFVS_OK_CIDR, DomainFilter::validate_entry("1.2.3.0/24"));
    ASSERT_EQ(DFVS_OK_ADDR, DomainFilter::validate_entry("[fd::]:80"));
    ASSERT_EQ(DFVS_OK_ADDR, DomainFilter::validate_entry("[fd::]"));
    ASSERT_EQ(DFVS_OK_ADDR, DomainFilter::validate_entry("fd::"));
    ASSERT_EQ(DFVS_OK_CIDR, DomainFilter::validate_entry("fd::/64"));
    ASSERT_EQ(DFVS_OK_DOMAIN, DomainFilter::validate_entry("*.google"));

    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry("1.1.1.1:0"));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry("1.2.3.0/33"));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry("google.*"));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry("*.google.*"));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry("1.2.3.4:65536"));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry("goo\"gle.com"));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry(" "));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry(""));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry(" example.org"));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry("."));
    ASSERT_EQ(DFVS_MALFORMED, DomainFilter::validate_entry(".."));
}
