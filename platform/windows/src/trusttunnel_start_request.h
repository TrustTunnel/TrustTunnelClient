#pragma once

#include <optional>
#include <string>
#include <vector>

#include "common/defs.h"

namespace ag::trusttunnel_windows {

/** A `TRUSTTUNNEL_SVC_MSG_START` request. */
struct StartRequest {
    /** If true, initial connection failures enter the recovery algorithm. */
    bool fall_into_recovery = false;
    /** The VPN client configuration in TOML format. */
    std::string toml_config;

    /**
     * Serialize the request into a `TRUSTTUNNEL_SVC_MSG_START` payload.
     * @return The message payload.
     */
    std::vector<uint8_t> serialize() const;

    /**
     * Deserialize a `TRUSTTUNNEL_SVC_MSG_START` payload.
     * @param data The message payload.
     * @return The parsed request, or `std::nullopt` if the payload is malformed.
     */
    static std::optional<StartRequest> deserialize(Uint8View data);
};

} // namespace ag::trusttunnel_windows
