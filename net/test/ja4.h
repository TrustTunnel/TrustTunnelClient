#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "common/defs.h"

namespace ag::ja4 {

/**
 * Compute the JA4 (https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
 * fingerprint of a ClientHello handshake message.
 * @param data The first TLS record sent by the client in case of TCP,
 *             or the first TLS Handshake message sent by the client in case of QUIC.
 * @param quic Whether `data` has been received, or is to be sent, over QUIC.
 * @return A JA4 fingerprint or an empty string in case of an error.
 */
std::string compute(ag::Uint8View data, bool quic);

} // namespace ag::ja4
