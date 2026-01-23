#include <gtest/gtest.h>

#include "common/file.h"
#include "memfile_buffer.h"
#include "vpn/utils.h"

using namespace ag;

// NOLINTBEGIN(bugprone-unchecked-optional-access))
class MemfileBufferTest : public testing::Test {
protected:
    const std::string FILE_PATH = "./test.dat";
    const std::string TEST_DATA_1 = "lalala";
    const std::string TEST_DATA_2 = "tratatata";
    const std::string COMPLETE_TEST_DATA = TEST_DATA_1 + TEST_DATA_2;

    std::unique_ptr<DataBuffer> buffer;

    void SetUp() override {
        buffer = std::make_unique<MemfileBuffer>("./test.dat", TEST_DATA_1.size());
        std::optional<std::string> err = buffer->init();
        ASSERT_FALSE(err.has_value()) << err.value();

        err = buffer->push({(uint8_t *) TEST_DATA_1.data(), TEST_DATA_1.size()});
        ASSERT_FALSE(err.has_value()) << err.value();
        ASSERT_EQ(buffer->size(), TEST_DATA_1.size());
        ASSERT_FALSE(fs::exists(FILE_PATH));

        err = buffer->push({(uint8_t *) TEST_DATA_2.data(), TEST_DATA_2.size()});
        ASSERT_FALSE(err.has_value()) << err.value();
        ASSERT_EQ(buffer->size(), TEST_DATA_1.size() + TEST_DATA_2.size());
        ASSERT_TRUE(fs::exists(FILE_PATH));
    }

    void TearDown() override {
        buffer.reset();
        ASSERT_FALSE(fs::exists(FILE_PATH));
    }

    void check_file_content(file::Handle fd, const std::string &expected) {
        ssize_t sz = file::get_size(fd);
        ASSERT_GE(sz, 0) << sys::strerror(sys::last_error());

        std::string content;
        content.resize(sz);
        ASSERT_EQ(file::read(fd, content.data(), content.size()), sz) << sys::strerror(sys::last_error());
        ASSERT_EQ(content, expected);
    }
};

// Check that peeked chunk remains in buffer
TEST_F(MemfileBufferTest, Peek) {
    size_t initial_size = buffer->size();

    BufferPeekResult res1 = buffer->peek();
    ASSERT_FALSE(res1.err.has_value()) << res1.err.value();
    ASSERT_LE(res1.data.size(), COMPLETE_TEST_DATA.size());
    ASSERT_EQ(buffer->size(), initial_size);

    size_t check_size = std::min(res1.data.size(), TEST_DATA_1.size());
    ASSERT_EQ(TEST_DATA_1.substr(0, check_size), std::string((char *) res1.data.data(), check_size));

    BufferPeekResult res2 = buffer->peek();
    ASSERT_FALSE(res2.err.has_value()) << res2.err.value();
    ASSERT_LE(res2.data.size(), COMPLETE_TEST_DATA.size());
    ASSERT_EQ(buffer->size(), initial_size);

    ASSERT_EQ(res1.data, res2.data);
}

TEST_F(MemfileBufferTest, Drain1) {
    size_t initial_size = buffer->size();
    std::string expected_data = COMPLETE_TEST_DATA;

    for (size_t i = 0; i < initial_size; ++i) {
        buffer->drain(1);
        ASSERT_EQ(buffer->size(), initial_size - i - 1);

        BufferPeekResult res = buffer->peek();
        ASSERT_FALSE(res.err.has_value()) << res.err.value();

        expected_data.erase(0, 1);
        ASSERT_EQ(expected_data.empty(), res.data.empty());

        if (!expected_data.empty()) {
            ASSERT_EQ(
                    expected_data.substr(0, res.data.size()), (std::string{(char *) res.data.data(), res.data.size()}));
        }
    }
}

TEST_F(MemfileBufferTest, Drain2) {
    std::string expected_data = COMPLETE_TEST_DATA;

    while (0 != buffer->size()) {
        BufferPeekResult res = buffer->peek();
        ASSERT_FALSE(res.err.has_value()) << res.err.value();
        ASSERT_FALSE(res.data.empty());
        ASSERT_EQ(expected_data.substr(0, res.data.size()), (std::string{(char *) res.data.data(), res.data.size()}));
        buffer->drain(res.data.size());
        expected_data.erase(0, res.data.size());
    }

    ASSERT_TRUE(expected_data.empty()) << expected_data;
}

TEST_F(MemfileBufferTest, FileContent) {
    file::Handle fd = file::open(FILE_PATH, file::RDONLY);
    ASSERT_NE(fd, file::INVALID_HANDLE) << sys::strerror(sys::last_error());

    // using EXPECT_* just to let it get to the end and close the descriptor

    EXPECT_EQ(file::get_size(fd), TEST_DATA_2.size()) << sys::strerror(sys::last_error());
    EXPECT_NO_FATAL_FAILURE(check_file_content(fd, TEST_DATA_2));

    file::close(fd);
    buffer->drain(TEST_DATA_1.size());
    std::optional<std::string> err = buffer->push({(uint8_t *) TEST_DATA_2.data(), TEST_DATA_2.size()});
    EXPECT_FALSE(err.has_value()) << err.value();

    // re-open as the old file should've been removed
    fd = file::open(FILE_PATH, 0);
    EXPECT_NE(fd, file::INVALID_HANDLE) << sys::strerror(sys::last_error());

    // at the moment 2 `TEST_DATA_2` are in buffer, as the memory cap is `TEST_DATA_1.size()`
    // file size should be:
    EXPECT_EQ(file::get_size(fd), 2 * TEST_DATA_2.size() - TEST_DATA_1.size()) << sys::strerror(sys::last_error());
    EXPECT_NO_FATAL_FAILURE(check_file_content(fd, TEST_DATA_2.substr(TEST_DATA_1.size()) + TEST_DATA_2));

    file::close(fd);
}
// NOLINTEND(bugprone-unchecked-optional-access)
