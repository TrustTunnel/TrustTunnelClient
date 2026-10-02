#include "trusttunnel_start_request.h"

#include "trusttunnel/trusttunnel_service.h"
#include "vpn/internal/wire_utils.h"

namespace ag::trusttunnel_windows {

static constexpr size_t FLAGS_SIZE = sizeof(uint32_t);

std::vector<uint8_t> StartRequest::serialize() const {
    std::vector<uint8_t> payload(FLAGS_SIZE + toml_config.size());
    wire_utils::Writer writer{{payload.data(), payload.size()}};
    writer.put_u32(fall_into_recovery ? TRUSTTUNNEL_SVC_START_FALL_INTO_RECOVERY : 0);
    if (!toml_config.empty()) {
        writer.put_data({(uint8_t *) toml_config.data(), toml_config.size()});
    }
    return payload;
}

std::optional<StartRequest> StartRequest::deserialize(Uint8View data) {
    wire_utils::Reader reader{data};
    std::optional<uint32_t> flags = reader.get_u32();
    if (!flags.has_value()) {
        return std::nullopt;
    }

    Uint8View toml = reader.get_buffer();
    return StartRequest{
            .fall_into_recovery = (*flags & TRUSTTUNNEL_SVC_START_FALL_INTO_RECOVERY) != 0,
            .toml_config = {(const char *) toml.data(), toml.size()},
    };
}

} // namespace ag::trusttunnel_windows
