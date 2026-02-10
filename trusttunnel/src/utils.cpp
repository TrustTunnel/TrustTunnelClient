#include "utils.h"

#include <magic_enum/magic_enum.hpp>

namespace ag {

static Logger g_logger("TrustTunnelCliUtils");

std::optional<ag::LogLevel> TrustTunnelCliUtils::parse_loglevel(std::string_view level) {
    static const std::unordered_map<std::string_view, ag::LogLevel> LOG_LEVEL_MAP = {
            {"error", ag::LOG_LEVEL_ERROR},
            {"warn", ag::LOG_LEVEL_WARN},
            {"info", ag::LOG_LEVEL_INFO},
            {"debug", ag::LOG_LEVEL_DEBUG},
            {"trace", ag::LOG_LEVEL_TRACE},
    };

    if (auto it = LOG_LEVEL_MAP.find(level); it != LOG_LEVEL_MAP.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool TrustTunnelCliUtils::apply_cmd_args(TrustTunnelConfig &config, const cxxopts::ParseResult &args) {
    if (args.count("s") > 0) {
        bool x = args["s"].as<bool>();
        if (x != config.location.skip_verification) {
            infolog(g_logger, "Skip verification value was overwritten: old={}, new={}",
                    config.location.skip_verification, x);
        }
        config.location.skip_verification = x;
    }
    if (args.count("loglevel") > 0) {
        if (auto loglevel = parse_loglevel(args["loglevel"].as<std::string>())) {
            if (loglevel != config.loglevel) {
                infolog(g_logger, "Log Level value was overwritten: old={}, new={}",
                        magic_enum::enum_name(config.loglevel), magic_enum::enum_name(*loglevel));
                config.loglevel = *loglevel;
            }
        } else {
            errlog(g_logger, "Unexpected log level: {}", args["loglevel"].as<std::string>());
            return false;
        }
    }
    return true;
}

} // namespace ag
