#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "trusttunnel_start_request.h"

namespace {

using namespace ag::trusttunnel_windows;

constexpr std::string_view TEST_TOML = "[endpoint]\nhostname = \"example.com\"\n";

StartRequest make_request(bool fall_into_recovery) {
    return StartRequest{
            .fall_into_recovery = fall_into_recovery,
            .toml_config = std::string{TEST_TOML},
    };
}

TEST(StartRequest, RoundTripWithFallIntoRecovery) {
    StartRequest source = make_request(true);
    std::vector<uint8_t> payload = source.serialize();
    std::optional<StartRequest> request = StartRequest::deserialize({payload.data(), payload.size()});
    ASSERT_TRUE(request.has_value());
    EXPECT_TRUE(request->fall_into_recovery);
    EXPECT_EQ(request->toml_config, source.toml_config);
}

TEST(StartRequest, RoundTripWithoutFallIntoRecovery) {
    StartRequest source = make_request(false);
    std::vector<uint8_t> payload = source.serialize();
    std::optional<StartRequest> request = StartRequest::deserialize({payload.data(), payload.size()});
    ASSERT_TRUE(request.has_value());
    EXPECT_FALSE(request->fall_into_recovery);
    EXPECT_EQ(request->toml_config, source.toml_config);
}

TEST(StartRequest, PreservesEmptyToml) {
    StartRequest source{.fall_into_recovery = true, .toml_config = {}};
    std::vector<uint8_t> payload = source.serialize();
    std::optional<StartRequest> request = StartRequest::deserialize({payload.data(), payload.size()});
    ASSERT_TRUE(request.has_value());
    EXPECT_TRUE(request->fall_into_recovery);
    EXPECT_TRUE(request->toml_config.empty());
}

TEST(StartRequest, RejectsEmptyPayload) {
    EXPECT_FALSE(StartRequest::deserialize(ag::Uint8View{}).has_value());
}

TEST(StartRequest, RejectsPayloadShorterThanFlags) {
    std::vector<uint8_t> payload{0x00, 0x00, 0x01};
    EXPECT_FALSE(StartRequest::deserialize({payload.data(), payload.size()}).has_value());
}

TEST(StartRequest, IgnoresUnknownFlagBits) {
    std::vector<uint8_t> payload = make_request(false).serialize();
    payload.front() |= 0x80; // an unknown flag bit in the first flags byte
    std::optional<StartRequest> request = StartRequest::deserialize({payload.data(), payload.size()});
    ASSERT_TRUE(request.has_value());
    EXPECT_FALSE(request->fall_into_recovery);
    EXPECT_EQ(request->toml_config, std::string{TEST_TOML});
}

} // namespace
