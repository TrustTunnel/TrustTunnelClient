#pragma once

#include "vpn/standalone/config.h"

#include <common/logger.h>
#include <cxxopts.hpp>

#include <optional>
#include <string_view>

namespace ag {

class StandaloneUtils {
public:
    static std::optional<ag::LogLevel> parse_loglevel(std::string_view level);

    static bool apply_cmd_args(VpnStandaloneConfig &config, const cxxopts::ParseResult &args);

    static void detect_bound_if(VpnStandaloneConfig &config);
};
} // namespace ag
