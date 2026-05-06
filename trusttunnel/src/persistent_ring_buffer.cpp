#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <vector>

#include "common/file.h"
#include "common/logger.h"
#include "vpn/platform.h"
#include "vpn/trusttunnel/persistent_ring_buffer.h"
#include "vpn/utils.h"

namespace fs = std::filesystem;

namespace ag {

static const Logger g_logger("PERSISTENT_RING_BUFFER"); // NOLINT(readability-identifier-naming)

struct Header {
    uint32_t magic;
    uint32_t version;
    uint32_t capacity;
    uint32_t max_record_bytes;
    uint32_t write_slot;
    uint32_t count;
    uint64_t next_sequence;
};

enum class ReadStatus {
    OK,
    INVALID,
    IO_ERROR,
};

static constexpr uint32_t FILE_MAGIC = 0x514c5242;
static constexpr uint32_t FILE_VERSION = 1;
static constexpr uint8_t SLOT_MARKER = 0xA5;
static constexpr size_t HEADER_SIZE = 32;
static constexpr size_t SLOT_SIZE = 1 + sizeof(uint32_t) + PersistentRingBuffer::MAX_RECORD_BYTES;

static std::string make_sys_error(const char *action) {
    return str_format("Failed to %s: %s (%d)", action, sys::strerror(sys::last_error()), sys::last_error());
}

static void log_error(std::string_view message) {
    errlog(g_logger, "{}", message);
}

static constexpr size_t total_file_size() {
    return HEADER_SIZE + PersistentRingBuffer::MAX_RECORDS * SLOT_SIZE;
}

static constexpr size_t slot_offset(uint32_t index) {
    return HEADER_SIZE + static_cast<size_t>(index) * SLOT_SIZE;
}

static void store_u32_le(uint8_t *dst, uint32_t value) {
    dst[0] = static_cast<uint8_t>(value & 0xff);
    dst[1] = static_cast<uint8_t>((value >> 8) & 0xff);
    dst[2] = static_cast<uint8_t>((value >> 16) & 0xff);
    dst[3] = static_cast<uint8_t>((value >> 24) & 0xff);
}

static void store_u64_le(uint8_t *dst, uint64_t value) {
    for (size_t i = 0; i < sizeof(value); ++i) {
        dst[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xff);
    }
}

static uint32_t load_u32_le(const uint8_t *src) {
    return static_cast<uint32_t>(src[0])
            | (static_cast<uint32_t>(src[1]) << 8)
            | (static_cast<uint32_t>(src[2]) << 16)
            | (static_cast<uint32_t>(src[3]) << 24);
}

static uint64_t load_u64_le(const uint8_t *src) {
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(value); ++i) {
        value |= static_cast<uint64_t>(src[i]) << (i * 8);
    }

    return value;
}

static std::array<uint8_t, HEADER_SIZE> serialize_header(const Header &header) {
    std::array<uint8_t, HEADER_SIZE> bytes{};
    store_u32_le(bytes.data() + 0, header.magic);
    store_u32_le(bytes.data() + 4, header.version);
    store_u32_le(bytes.data() + 8, header.capacity);
    store_u32_le(bytes.data() + 12, header.max_record_bytes);
    store_u32_le(bytes.data() + 16, header.write_slot);
    store_u32_le(bytes.data() + 20, header.count);
    store_u64_le(bytes.data() + 24, header.next_sequence);
    return bytes;
}

static Header deserialize_header(const uint8_t *bytes) {
    return Header{
            .magic = load_u32_le(bytes + 0),
            .version = load_u32_le(bytes + 4),
            .capacity = load_u32_le(bytes + 8),
            .max_record_bytes = load_u32_le(bytes + 12),
            .write_slot = load_u32_le(bytes + 16),
            .count = load_u32_le(bytes + 20),
            .next_sequence = load_u64_le(bytes + 24),
    };
}

static std::optional<std::string> write_exact(file::Handle fd, const uint8_t *data, size_t size) {
    size_t written = 0;
    while (written < size) {
        ssize_t result = file::write(fd, data + written, size - written);
        if (result <= 0) {
            return make_sys_error("write file data");
        }

        written += static_cast<size_t>(result);
    }

    return std::nullopt;
}

static std::optional<std::string> write_at(file::Handle fd, size_t pos, const uint8_t *data, size_t size) {
    if (file::set_position(fd, pos) < 0) {
        return make_sys_error("set file position");
    }

    return write_exact(fd, data, size);
}

static ReadStatus read_exact_at(file::Handle fd, uint8_t *data, size_t size, size_t pos) {
    size_t read_size = 0;
    while (read_size < size) {
        ssize_t result = file::pread(fd, reinterpret_cast<char *>(data + read_size), size - read_size, pos + read_size);
        if (result < 0) {
            log_error(make_sys_error("read file data"));
            return ReadStatus::IO_ERROR;
        }

        if (result == 0) {
            return ReadStatus::INVALID;
        }

        read_size += static_cast<size_t>(result);
    }

    return ReadStatus::OK;
}

static std::optional<std::string> write_header(file::Handle fd, const Header &header) {
    auto bytes = serialize_header(header);
    return write_at(fd, 0, bytes.data(), bytes.size());
}

static ReadStatus read_valid_header(file::Handle fd, Header *header) {
    ssize_t size = file::get_size(fd);
    if (size < 0) {
        log_error(make_sys_error("get file size"));
        return ReadStatus::IO_ERROR;
    }

    if (static_cast<size_t>(size) != total_file_size()) {
        return ReadStatus::INVALID;
    }

    std::array<uint8_t, HEADER_SIZE> bytes{};
    ReadStatus status = read_exact_at(fd, bytes.data(), bytes.size(), 0);
    if (status != ReadStatus::OK) {
        return status;
    }

    *header = deserialize_header(bytes.data());
    if (header->magic != FILE_MAGIC
            || header->version != FILE_VERSION
            || header->capacity != PersistentRingBuffer::MAX_RECORDS
            || header->max_record_bytes != PersistentRingBuffer::MAX_RECORD_BYTES
            || header->write_slot >= header->capacity
            || header->count > header->capacity
            || header->next_sequence < header->count) {
        return ReadStatus::INVALID;
    }

    return ReadStatus::OK;
}

static std::optional<std::string> reset_file(const std::string &path) {
    file::Handle fd = file::open(path, file::CREAT | file::TRUNC | file::RDWR);
    if (fd == file::INVALID_HANDLE) {
        return make_sys_error("open ring buffer file");
    }

    std::vector<uint8_t> data(total_file_size(), 0);
    Header header = {
            .magic = FILE_MAGIC,
            .version = FILE_VERSION,
            .capacity = PersistentRingBuffer::MAX_RECORDS,
            .max_record_bytes = PersistentRingBuffer::MAX_RECORD_BYTES,
            .write_slot = 0,
            .count = 0,
            .next_sequence = 0,
    };
    auto header_bytes = serialize_header(header);
    std::memcpy(data.data(), header_bytes.data(), header_bytes.size());

    std::optional<std::string> error = write_exact(fd, data.data(), data.size());
    file::close(fd);
    return error;
}

static file::Handle open_valid_buffer(const std::string &path, Header *header) {
    file::Handle fd = file::open(path, file::CREAT | file::RDWR);
    if (fd == file::INVALID_HANDLE) {
        log_error(make_sys_error("open ring buffer file"));
        return file::INVALID_HANDLE;
    }

    ReadStatus status = read_valid_header(fd, header);
    if (status == ReadStatus::OK) {
        return fd;
    }

    file::close(fd);
    if (status == ReadStatus::IO_ERROR) {
        return file::INVALID_HANDLE;
    }

    if (std::optional<std::string> reset_error = reset_file(path); reset_error.has_value()) {
        log_error(reset_error.value());
        return file::INVALID_HANDLE;
    }

    fd = file::open(path, file::CREAT | file::RDWR);
    if (fd == file::INVALID_HANDLE) {
        log_error(make_sys_error("reopen ring buffer file"));
        return file::INVALID_HANDLE;
    }

    status = read_valid_header(fd, header);
    if (status != ReadStatus::OK) {
        file::close(fd);
        if (status == ReadStatus::INVALID) {
            log_error("Failed to initialize ring buffer header");
        }
        return file::INVALID_HANDLE;
    }

    return fd;
}

static std::optional<std::string> write_record_slot(file::Handle fd, uint32_t slot_index, std::string_view record) {
    std::vector<uint8_t> slot(SLOT_SIZE, 0);
    slot[0] = SLOT_MARKER;
    store_u32_le(slot.data() + 1, static_cast<uint32_t>(record.size()));
    if (!record.empty()) {
        std::memcpy(slot.data() + 1 + sizeof(uint32_t), record.data(), record.size());
    }

    return write_at(fd, slot_offset(slot_index), slot.data(), slot.size());
}

static ReadStatus read_record_slot(file::Handle fd, uint32_t slot_index, std::string *record) {
    std::vector<uint8_t> slot(SLOT_SIZE, 0);
    ReadStatus status = read_exact_at(fd, slot.data(), slot.size(), slot_offset(slot_index));
    if (status != ReadStatus::OK) {
        return status;
    }

    if (slot[0] != SLOT_MARKER) {
        return ReadStatus::INVALID;
    }

    uint32_t length = load_u32_le(slot.data() + 1);
    if (length > PersistentRingBuffer::MAX_RECORD_BYTES) {
        return ReadStatus::INVALID;
    }

    record->assign(reinterpret_cast<const char *>(slot.data() + 1 + sizeof(uint32_t)), length);
    return ReadStatus::OK;
}

PersistentRingBuffer::PersistentRingBuffer(std::string path)
        : m_path(std::move(path)) {
}

bool PersistentRingBuffer::append(std::string_view record) {
    if (record.size() > MAX_RECORD_BYTES) {
        log_error(str_format("Record exceeds maximum size: %zu > %u", record.size(), MAX_RECORD_BYTES));
        return false;
    }

    Header header{};
    file::Handle fd = open_valid_buffer(m_path, &header);
    if (fd == file::INVALID_HANDLE) {
        return false;
    }

    std::optional<std::string> write_error = write_record_slot(fd, header.write_slot, record);
    if (!write_error.has_value()) {
        header.write_slot = (header.write_slot + 1) % header.capacity;
        header.count = std::min(header.count + 1, header.capacity);
        ++header.next_sequence;
        write_error = write_header(fd, header);
    }

    file::close(fd);
    if (write_error.has_value()) {
        log_error(write_error.value());
        return false;
    }

    return true;
}

std::optional<RingBufferReadResult> PersistentRingBuffer::read_all() const {
    return read_since(std::nullopt);
}

std::optional<RingBufferReadResult> PersistentRingBuffer::read_since(std::optional<uint64_t> next_sequence) const {
    Header header{};
    file::Handle fd = open_valid_buffer(m_path, &header);
    if (fd == file::INVALID_HANDLE) {
        return std::nullopt;
    }

    uint64_t earliest_retained = header.next_sequence - header.count;
    uint64_t start_sequence = next_sequence.value_or(earliest_retained);
    start_sequence = std::clamp(start_sequence, earliest_retained, header.next_sequence);

    RingBufferReadResult result;
    result.next_sequence = header.next_sequence;
    result.records.reserve(header.next_sequence - start_sequence);

    for (uint64_t sequence = start_sequence; sequence < header.next_sequence; ++sequence) {
        std::string record;
        ReadStatus status = read_record_slot(fd, sequence % header.capacity, &record);
        if (status == ReadStatus::OK) {
            result.records.push_back(std::move(record));
            continue;
        }

        file::close(fd);
        if (status == ReadStatus::IO_ERROR) {
            return std::nullopt;
        }

        if (std::optional<std::string> reset_error = reset_file(m_path); reset_error.has_value()) {
            log_error(reset_error.value());
            return std::nullopt;
        }

        return RingBufferReadResult{};
    }

    file::close(fd);
    return result;
}

bool PersistentRingBuffer::clear() {
    std::error_code error_code;
    fs::remove(m_path, error_code);
    if (error_code) {
        log_error(str_format("Failed to remove ring buffer file: %s", error_code.message().c_str()));
        return false;
    }

    return true;
}

} // namespace ag