#pragma once

#include "common/file.h"
#include "vpn/internal/data_buffer.h"

namespace ag {

class MemfileBuffer : public DataBuffer {
public:
    /**
     * @param path file path
     * @param mem_threshold memory buffer size (exceeding this limit causes storing incoming data in file)
     * @param max_file_size maximum file size (exceeding this limit causes data truncation)
     */
    MemfileBuffer(std::string path, size_t mem_threshold, size_t max_file_size = SIZE_MAX);
    ~MemfileBuffer() override;

    MemfileBuffer(const MemfileBuffer &) = delete;
    MemfileBuffer &operator=(const MemfileBuffer &) = delete;

    MemfileBuffer(MemfileBuffer &&) noexcept = delete;
    MemfileBuffer &operator=(MemfileBuffer &&) noexcept = delete;

private:
    std::unique_ptr<DataBuffer> m_mem_buffer; // memory buffer
    size_t m_threshold = 0;                   // memory buffer theshold
    size_t m_max_file_size = SIZE_MAX;        // maximum file size
    file::Handle m_fd = file::INVALID_HANDLE; // file descriptor
    size_t m_read_offset = 0;                 // file read offset
    std::string m_path;                       // full file path

    std::optional<std::string> init() override;
    [[nodiscard]] size_t size() const override;
    std::optional<std::string> push(U8View data) override;
    std::optional<std::string> push(std::vector<uint8_t> data) override;
    BufferPeekResult peek() override;
    void drain(size_t length) override;

    /** Fill free space in memory buffer with file content */
    std::optional<std::string> transfer_file2mem();
    /** Fill free space in memory buffer with given data */
    std::vector<uint8_t> transfer_mem2mem(std::vector<uint8_t> data);
    U8View transfer_mem2mem(U8View data);
    /** Get free space size in memory buffer */
    [[nodiscard]] size_t get_free_mem_space() const;
    /** Check if read part needs to be stripped from file */
    [[nodiscard]] bool need_to_strip_file(size_t fsize, size_t data_size) const;
    /** Strip read part from file */
    std::optional<std::string> strip_file();
    /** Write data in file */
    std::optional<std::string> write_in_file(U8View data);
};

} // namespace ag
