#pragma once

#include "vpn/trusttunnel/config.h"

#include <common/logger.h>
#include <cxxopts.hpp>

#include <optional>
#include <string_view>

namespace ag {

class TrustTunnelCliUtils {
public:
    static std::optional<ag::LogLevel> parse_loglevel(std::string_view level);

    static bool apply_cmd_args(TrustTunnelConfig &config, const cxxopts::ParseResult &args);
};
} // namespace ag
