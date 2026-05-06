#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ag {

struct RingBufferReadResult {
    std::vector<std::string> records;
    uint64_t next_sequence = 0;
};

class PersistentRingBuffer {
public:
    static constexpr uint32_t MAX_RECORDS = 500;
    static constexpr uint32_t MAX_RECORD_BYTES = 1024;

    /// Create a persistent ring buffer backed by a file at `path`.
    /// Changing `max_records` or `max_record_bytes` after data has been written
    /// will cause the existing file to be treated as corrupted. Call `clear()`
    /// first to start fresh with new parameters.
    explicit PersistentRingBuffer(
            std::string path, uint32_t max_records = MAX_RECORDS, uint32_t max_record_bytes = MAX_RECORD_BYTES);

    bool append(std::string_view record);
    std::optional<RingBufferReadResult> read_all() const;
    std::optional<RingBufferReadResult> read_since(std::optional<uint64_t> next_sequence) const;
    bool clear();

private:
    std::string m_path;
    uint32_t m_max_records;
    uint32_t m_max_record_bytes;
};

} // namespace ag