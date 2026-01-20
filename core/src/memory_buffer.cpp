#include "memory_buffer.h"

#include <algorithm>
#include <cassert>

namespace ag {

MemoryBuffer::MemoryBuffer() = default;

MemoryBuffer::~MemoryBuffer() = default;

std::optional<std::string> MemoryBuffer::init() {
    return std::nullopt;
}

size_t MemoryBuffer::size() const {
    return m_total_size;
}

std::optional<std::string> MemoryBuffer::push(U8View data) {
    return push(std::vector<uint8_t>(data.data(), data.data() + data.length()));
}

std::optional<std::string> MemoryBuffer::push(std::vector<uint8_t> data) {
    if (!data.empty()) {
        m_total_size += data.size();
        m_chunks.emplace(std::move(data));
    }
    return std::nullopt;
}

BufferPeekResult MemoryBuffer::peek() {
    U8View chunk;
    if (!m_chunks.empty()) {
        const std::vector<uint8_t> &front = m_chunks.front();
        chunk = {front.data(), front.size()};
    }
    return {std::nullopt, chunk};
}

void MemoryBuffer::drain(size_t length) {
    assert(length <= m_total_size);
    m_total_size -= length;

    while (length > 0) {
        assert(!m_chunks.empty());

        std::vector<uint8_t> &front = m_chunks.front();
        size_t to_remove = std::min(front.size(), length);
        // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
        front.erase(front.begin(), front.begin() + to_remove);

        length -= to_remove;
        if (front.empty()) {
            m_chunks.pop();
        }
    }
}

} // namespace ag
