#include <algorithm>
#include <cassert>
#include <filesystem>

#include "memfile_buffer.h"
#include "memory_buffer.h"
#include "vpn/platform.h"

namespace ag {

MemfileBuffer::MemfileBuffer(std::string path, size_t mem_threshold, size_t max_file_size)
        : m_mem_buffer(std::make_unique<MemoryBuffer>())
        , m_threshold(mem_threshold)
        , m_max_file_size(max_file_size)
        , m_path(std::move(path)) {
    assert(!m_path.empty());
}

MemfileBuffer::~MemfileBuffer() {
    file::close(std::exchange(m_fd, file::INVALID_HANDLE));

    if (!m_path.empty()) {
        std::error_code err;
        std::filesystem::remove(m_path, err);
    }
}

std::optional<std::string> MemfileBuffer::init() {
    return m_mem_buffer->init();
}

size_t MemfileBuffer::size() const {
    ssize_t fsize = (m_fd != file::INVALID_HANDLE) ? file::get_size(m_fd) : 0;
    assert(fsize >= (ssize_t) m_read_offset);

    size_t stored_in_file = std::max(fsize, (ssize_t) 0) - m_read_offset;

    return m_mem_buffer->size() + stored_in_file;
}

std::optional<std::string> MemfileBuffer::push(U8View data) {
    data = transfer_mem2mem(data);
    return write_in_file(data);
}

std::optional<std::string> MemfileBuffer::push(std::vector<uint8_t> data) {
    data = transfer_mem2mem(std::move(data));
    return write_in_file({data.data(), data.size()});
}

BufferPeekResult MemfileBuffer::peek() {
    BufferPeekResult r = {transfer_file2mem()};
    return !r.err.has_value() ? m_mem_buffer->peek() : r;
}

void MemfileBuffer::drain(size_t length) {
    m_mem_buffer->drain(length);
    transfer_file2mem();
}

size_t MemfileBuffer::get_free_mem_space() const {
    return m_threshold - m_mem_buffer->size();
}

std::optional<std::string> MemfileBuffer::transfer_file2mem() {
    if (m_fd == file::INVALID_HANDLE) {
        return std::nullopt;
    }

    size_t free_space = get_free_mem_space();
    if (free_space == 0) {
        return std::nullopt;
    }

    ssize_t fsize = file::get_size(m_fd);
    if (fsize == 0) {
        return std::nullopt;
    }
    if (fsize < 0) {
        return str_format("Failed to get file size: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
    }

    assert(fsize >= (ssize_t) m_read_offset);

    size_t to_read = std::min(free_space, (size_t) (fsize - m_read_offset));
    if ((size_t) fsize == m_read_offset) {
        return std::nullopt;
    }

    ssize_t r = file::set_position(m_fd, m_read_offset);
    if (r < 0) {
        return str_format("Failed to set file offset: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
    }

    std::vector<uint8_t> buf;
    buf.resize(to_read);

    uint8_t *buf_pos = buf.data();
    uint8_t *buf_end = buf_pos + buf.size();

    while (buf_pos != buf_end) {
        ssize_t ret = file::read(m_fd, (char *) buf_pos, buf_end - buf_pos);
        if (ret > 0) {
            buf_pos += ret;
            m_read_offset += ret;
        } else if (ret == 0) {
            return str_format("Unexpected EOF while reading file content");
        } else {
            return str_format(
                    "Failed to read file content: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
        }
    }

    return m_mem_buffer->push(std::move(buf));
}

std::vector<uint8_t> MemfileBuffer::transfer_mem2mem(std::vector<uint8_t> data) {
    size_t free_space = get_free_mem_space();
    if (free_space == 0) {
        return data;
    }

    std::vector<uint8_t> chunk;
    if (free_space >= data.size()) {
        chunk.swap(data);
    } else {
        chunk = {data.data(), data.data() + free_space};
    }

    if (std::optional<std::string> err = m_mem_buffer->push(chunk); !err.has_value()) {
        data.erase(data.begin(), data.begin() + chunk.size());
    }

    return data;
}

U8View MemfileBuffer::transfer_mem2mem(U8View data) {
    size_t free_space = get_free_mem_space();
    if (free_space == 0) {
        return data;
    }

    U8View chunk;
    if (free_space >= data.size()) {
        chunk = data;
    } else {
        chunk = {data.data(), free_space};
    }

    if (std::optional<std::string> err = m_mem_buffer->push(chunk); !err.has_value()) {
        data.remove_prefix(chunk.size());
    }

    return data;
}

static std::optional<std::string> transfer_file2file(file::Handle dst, file::Handle src, size_t size) {
    if (size == 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> buf(size);
    size_t buf_pos = 0;

    while (buf_pos < buf.size()) {
        ssize_t r = file::read(src, (char *) buf.data(), buf.size() - buf_pos);
        if (r > 0) {
            buf_pos += r;
        } else if (r == 0) {
            return str_format("Unexpected EOF while reading file content");
        } else {
            return str_format("%s (%d)", sys::strerror(sys::last_error()), sys::last_error());
        }
    }

    buf_pos = 0;
    while (buf_pos < buf.size()) {
        int r = file::write(dst, buf.data(), buf.size() - buf_pos);
        if (r > 0) {
            buf_pos += r;
        } else {
            return str_format("%s (%d)", sys::strerror(sys::last_error()), sys::last_error());
        }
    }

    return std::nullopt;
}

bool MemfileBuffer::need_to_strip_file(size_t fsize, size_t data_size) const {
    return fsize + data_size > m_max_file_size
            || (m_read_offset > 0
                    // current position is more than 30% of the file size
                    && (m_read_offset > (m_max_file_size * 3 / 10)
                            || m_read_offset > (fsize * 3 / 10)
                            // file reached 80% of its maximum size
                            || fsize > (m_max_file_size * 8 / 10)));
}

std::optional<std::string> MemfileBuffer::strip_file() {
    ssize_t fsize = file::get_size(m_fd);
    if (fsize < 0) {
        return str_format("Failed to get file size: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
    }

    assert(fsize >= (ssize_t) m_read_offset);

    file::close(std::exchange(m_fd, file::INVALID_HANDLE));
    std::string tmp_fpath = str_format("%s.tmp", m_path.c_str());

    std::error_code fs_err;
    std::filesystem::rename(m_path, tmp_fpath, fs_err);
    if (fs_err) {
        return str_format("Failed to rename file: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
    }

    std::optional<std::string> err;
    file::Handle tmp_fd = file::INVALID_HANDLE;
    m_fd = file::open(m_path, file::CREAT | file::APPEND | file::RDWR);
    if (m_fd == file::INVALID_HANDLE) {
        err = str_format("Failed to open file: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
        goto exit;
    }

    tmp_fd = file::open(tmp_fpath, file::RDONLY);
    if (tmp_fd == file::INVALID_HANDLE) {
        err = str_format("Failed to open temp file: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
        goto exit;
    }

    if (0 > file::set_position(tmp_fd, m_read_offset)) {
        err = str_format("Failed to set file offset: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
        goto exit;
    }

    err = transfer_file2file(m_fd, tmp_fd, fsize - m_read_offset);
    if (err.has_value()) {
        err = str_format("Failed to transfer file content: %s", err->c_str());
        goto exit;
    }

    m_read_offset = 0;

exit:
    file::close(tmp_fd);
    if (err.has_value()) {
        file::close(std::exchange(m_fd, file::INVALID_HANDLE));
        std::filesystem::remove(m_path, fs_err);
        fs_err.clear();
        std::filesystem::rename(tmp_fpath, m_path, fs_err);
        if (!fs_err) {
            m_fd = file::open(m_path, file::APPEND | file::RDWR);
        }
    }
    std::filesystem::remove(tmp_fpath, fs_err);

    return err;
}

std::optional<std::string> MemfileBuffer::write_in_file(U8View data) {
    if (data.empty()) {
        return std::nullopt;
    }

    if (m_fd == file::INVALID_HANDLE) {
        m_fd = file::open(m_path, file::CREAT | file::APPEND | file::RDWR);
        if (m_fd == file::INVALID_HANDLE) {
            return str_format("Failed to open file: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
        }
    }

    int64_t fsize = file::get_size(m_fd);
    if (fsize < 0) {
        return str_format("Failed to get file size: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
    }

    if (need_to_strip_file(size_t(fsize), data.size())) {
        if (std::optional<std::string> err = strip_file(); err.has_value()) {
            return str_format("Failed to strip file: %s", err->c_str());
        }
    }

    size_t to_write = 0;
    fsize = file::get_size(m_fd);
    if (fsize < 0) {
        return str_format("Failed to get file size: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
    }
    if ((size_t) fsize >= m_max_file_size) {
        return "File reached its capacity";
    }

    to_write = std::min(data.size(), (size_t) (m_max_file_size - fsize));

    data = {data.data(), to_write};
    if (!data.empty() && 0 >= file::write(m_fd, data.data(), data.size())) {
        return str_format("Failed to write data: %s (%d)", sys::strerror(sys::last_error()), sys::last_error());
    }

    return std::nullopt;
}

} // namespace ag
