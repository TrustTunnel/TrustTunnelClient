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

    explicit PersistentRingBuffer(std::string path);

    bool append(std::string_view record);
    std::optional<RingBufferReadResult> read_all() const;
    std::optional<RingBufferReadResult> read_since(std::optional<uint64_t> next_sequence) const;
    bool clear();

private:
    std::string m_path;
};

} // namespace ag