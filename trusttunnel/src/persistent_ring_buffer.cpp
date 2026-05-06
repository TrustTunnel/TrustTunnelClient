#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <vector>

#include "common/autofd.h"
#include "common/file.h"
#include "common/logger.h"
#include "common/system_error.h"
#include "vpn/platform.h"
#include "vpn/trusttunnel/persistent_ring_buffer.h"

namespace fs = std::filesystem;

namespace ag {

static const Logger g_logger("PERSISTENT_RING_BUFFER"); // NOLINT(readability-identifier-naming)

// -- File layout --

static constexpr uint32_t FILE_MAGIC = 0x514c5242;
static constexpr uint32_t FILE_VERSION = 1;
static constexpr char SLOT_MARKER = 'R';
static constexpr size_t SLOT_MARKER_SIZE = sizeof(SLOT_MARKER);
static constexpr size_t SLOT_LENGTH_SIZE = sizeof(uint32_t);

struct Header {
    uint32_t magic;
    uint32_t version;
    uint32_t capacity;
    uint32_t max_record_bytes;
    uint32_t write_slot;
    uint32_t count;
    uint64_t next_sequence;
};

static_assert(sizeof(Header) == 32, "Header must be 32 bytes with no padding");

// -- Low-level I/O --

/// Write data at the given file position
static bool write_at(file::Handle fd, size_t pos, const void *data, size_t size) {
    if (file::set_position(fd, pos) < 0) {
        errlog(g_logger, "Failed to set file position: {} ({})", sys::strerror(sys::last_error()), sys::last_error());
        return false;
    }

    auto *ptr = static_cast<const char *>(data);
    size_t written = 0;
    while (written < size) {
        ssize_t result = file::write(fd, ptr + written, size - written);
        if (result <= 0) {
            errlog(g_logger, "Failed to write: {} ({})", sys::strerror(sys::last_error()), sys::last_error());
            return false;
        }
        written += result;
    }
    return true;
}

/// Read exactly `size` bytes at the given file position
static bool read_at(file::Handle fd, void *data, size_t size, size_t pos) {
    auto *ptr = static_cast<char *>(data);
    size_t total = 0;
    while (total < size) {
        ssize_t result = file::pread(fd, ptr + total, size - total, pos + total);
        if (result < 0) {
            errlog(g_logger, "Failed to read: {} ({})", sys::strerror(sys::last_error()), sys::last_error());
            return false;
        }
        if (result == 0) {
            errlog(g_logger, "Unexpected end of file at position {}", pos + total);
            return false;
        }
        total += result;
    }
    return true;
}

/// Context for reading and writing a ring buffer file
class BufferFile {
public:
    BufferFile(file::Handle fd, uint32_t max_records, uint32_t max_record_bytes)
            : m_fd(fd)
            , m_max_records(max_records)
            , m_max_record_bytes(max_record_bytes) {
    }

    bool read_header(Header *header) const {
        if (!read_at(m_fd, header, sizeof(Header), 0)) {
            return false;
        }
        return header->magic == FILE_MAGIC && header->version == FILE_VERSION && header->capacity == m_max_records
                && header->max_record_bytes == m_max_record_bytes && header->write_slot < header->capacity
                && header->count <= header->capacity && header->next_sequence >= header->count;
    }

    bool write_header(const Header &header) const {
        return write_at(m_fd, 0, &header, sizeof(header));
    }

    bool write_slot(uint32_t slot_index, std::string_view record) const {
        size_t size = slot_size();
        std::vector<char> slot(size, 0);
        slot[0] = SLOT_MARKER;
        auto length = static_cast<uint32_t>(record.size());
        std::memcpy(slot.data() + SLOT_MARKER_SIZE, &length, sizeof(length));
        if (!record.empty()) {
            std::memcpy(slot.data() + SLOT_MARKER_SIZE + SLOT_LENGTH_SIZE, record.data(), record.size());
        }
        return write_at(m_fd, slot_offset(slot_index), slot.data(), slot.size());
    }

    bool read_slot(uint32_t slot_index, std::string *record) const {
        size_t size = slot_size();
        std::vector<char> slot(size);
        if (!read_at(m_fd, slot.data(), slot.size(), slot_offset(slot_index))) {
            errlog(g_logger, "Failed to read slot {}", slot_index);
            return false;
        }

        if (slot[0] != SLOT_MARKER) {
            errlog(g_logger, "Invalid slot marker at slot {}", slot_index);
            return false;
        }

        uint32_t length = 0;
        std::memcpy(&length, slot.data() + SLOT_MARKER_SIZE, sizeof(length));
        if (length > m_max_record_bytes) {
            errlog(g_logger, "Slot {} record length {} exceeds maximum {}", slot_index, length, m_max_record_bytes);
            return false;
        }

        record->assign(slot.data() + SLOT_MARKER_SIZE + SLOT_LENGTH_SIZE, length);
        return true;
    }

private:
    size_t slot_size() const {
        return SLOT_MARKER_SIZE + SLOT_LENGTH_SIZE + m_max_record_bytes;
    }

    size_t slot_offset(uint32_t index) const {
        return sizeof(Header) + index * slot_size();
    }

    file::Handle m_fd;
    uint32_t m_max_records;
    uint32_t m_max_record_bytes;
};

// -- Public API --

PersistentRingBuffer::PersistentRingBuffer(std::string path, uint32_t max_records, uint32_t max_record_bytes)
        : m_path(std::move(path))
        , m_max_records(max_records)
        , m_max_record_bytes(max_record_bytes) {
}

bool PersistentRingBuffer::append(std::string_view record) {
    if (record.size() > m_max_record_bytes) {
        errlog(g_logger, "Record exceeds maximum size: {} > {}", record.size(), m_max_record_bytes);
        return false;
    }

    bool created = !fs::exists(m_path);
    AutoFd fd = AutoFd::adopt_fd(file::open(m_path, file::CREAT | file::RDWR));
    if (!fd.is_valid()) {
        errlog(g_logger, "Failed to open ring buffer file: {} ({})", sys::strerror(sys::last_error()),
                sys::last_error());
        return false;
    }

    BufferFile buf(fd.get(), m_max_records, m_max_record_bytes);
    Header header{};
    if (created) {
        infolog(g_logger, "Creating new ring buffer file");
        header = {
                .magic = FILE_MAGIC,
                .version = FILE_VERSION,
                .capacity = m_max_records,
                .max_record_bytes = m_max_record_bytes,
                .write_slot = 0,
                .count = 0,
                .next_sequence = 0,
        };
        if (!buf.write_header(header)) {
            errlog(g_logger, "Failed to write header to new ring buffer file");
            return false;
        }
    }

    if (!buf.read_header(&header)) {
        errlog(g_logger, "Ring buffer file is corrupted");
        return false;
    }

    if (!buf.write_slot(header.write_slot, record)) {
        errlog(g_logger, "Failed to write record to slot {}", header.write_slot);
        return false;
    }

    header.write_slot = (header.write_slot + 1) % header.capacity;
    header.count = std::min(header.count + 1, header.capacity);
    ++header.next_sequence;
    if (!buf.write_header(header)) {
        errlog(g_logger, "Failed to update header after writing record");
        return false;
    }
    return true;
}

std::optional<RingBufferReadResult> PersistentRingBuffer::read_all() const {
    return read_since(std::nullopt);
}

std::optional<RingBufferReadResult> PersistentRingBuffer::read_since(std::optional<uint64_t> next_sequence) const {
    if (!fs::exists(m_path)) {
        return RingBufferReadResult{};
    }

    AutoFd fd = AutoFd::adopt_fd(file::open(m_path, file::RDONLY));
    if (!fd.is_valid()) {
        errlog(g_logger, "Failed to open ring buffer file: {} ({})", sys::strerror(sys::last_error()),
                sys::last_error());
        return std::nullopt;
    }

    BufferFile buf(fd.get(), m_max_records, m_max_record_bytes);
    Header header{};
    if (!buf.read_header(&header)) {
        errlog(g_logger, "Ring buffer file is corrupted");
        return std::nullopt;
    }

    uint64_t earliest_retained = header.next_sequence - header.count;
    uint64_t start_sequence =
            std::clamp(next_sequence.value_or(earliest_retained), earliest_retained, header.next_sequence);

    RingBufferReadResult result;
    result.next_sequence = header.next_sequence;
    result.records.reserve(header.next_sequence - start_sequence);

    for (uint64_t seq = start_sequence; seq < header.next_sequence; ++seq) {
        std::string record;
        if (!buf.read_slot(seq % header.capacity, &record)) {
            errlog(g_logger, "Failed to read record at sequence {}", seq);
            return std::nullopt;
        }
        result.records.push_back(std::move(record));
    }

    return result;
}

bool PersistentRingBuffer::clear() {
    std::error_code error_code;
    fs::remove(m_path, error_code);
    if (error_code) {
        errlog(g_logger, "Failed to remove ring buffer file: {}", error_code.message());
        return false;
    }
    return true;
}

} // namespace ag