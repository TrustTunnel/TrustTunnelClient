#include <gtest/gtest.h>

#include "memory_buffer.h"

using namespace ag;

// NOLINTBEGIN(bugprone-unchecked-optional-access)
class MemoryBufferTest : public testing::Test {
protected:
    const std::string TEST_DATA_1 = "tratata";
    const std::string TEST_DATA_2 = "lalala";
    const std::string COMPLETE_TEST_DATA = TEST_DATA_1 + TEST_DATA_2;

    std::unique_ptr<DataBuffer> m_buffer;

    void SetUp() override {
        m_buffer = std::make_unique<MemoryBuffer>();
        std::optional<std::string> err = m_buffer->init();
        ASSERT_FALSE(err.has_value()) << err.value();

        err = m_buffer->push({(uint8_t *) TEST_DATA_1.data(), TEST_DATA_1.size()});
        ASSERT_FALSE(err.has_value()) << err.value();
        ASSERT_EQ(m_buffer->size(), TEST_DATA_1.size());

        err = m_buffer->push({(uint8_t *) TEST_DATA_2.data(), TEST_DATA_2.size()});
        ASSERT_FALSE(err.has_value()) << err.value();
        ASSERT_EQ(m_buffer->size(), TEST_DATA_1.size() + TEST_DATA_2.size());
    }

    void TearDown() override {
        m_buffer.reset();
    }
};

// Check that peeked chunk remains in buffer
TEST_F(MemoryBufferTest, Peek) {
    size_t initial_size = m_buffer->size();

    BufferPeekResult res1 = m_buffer->peek();
    ASSERT_FALSE(res1.err.has_value()) << res1.err.value();
    ASSERT_LE(res1.data.size(), COMPLETE_TEST_DATA.size());
    ASSERT_EQ(m_buffer->size(), initial_size);

    size_t check_size = std::min(res1.data.size(), TEST_DATA_1.size());
    ASSERT_EQ(TEST_DATA_1.substr(0, check_size), (std::string{(char *) res1.data.data(), check_size}));

    BufferPeekResult res2 = m_buffer->peek();
    ASSERT_FALSE(res2.err.has_value()) << res2.err.value();
    ASSERT_LE(res2.data.size(), COMPLETE_TEST_DATA.size());
    ASSERT_EQ(m_buffer->size(), initial_size);

    ASSERT_EQ(res1.data, res2.data);
}

TEST_F(MemoryBufferTest, Drain1) {
    size_t initial_size = m_buffer->size();
    std::string expected_data = COMPLETE_TEST_DATA;

    for (size_t i = 0; i < initial_size; ++i) {
        m_buffer->drain(1);
        ASSERT_EQ(m_buffer->size(), initial_size - i - 1);

        BufferPeekResult res = m_buffer->peek();
        ASSERT_FALSE(res.err.has_value()) << res.err.value();

        expected_data.erase(0, 1);
        ASSERT_EQ(expected_data.empty(), res.data.empty());

        if (!expected_data.empty()) {
            ASSERT_EQ(
                    expected_data.substr(0, res.data.size()), (std::string{(char *) res.data.data(), res.data.size()}));
        }
    }
}

TEST_F(MemoryBufferTest, Drain2) {
    std::string expected_data = COMPLETE_TEST_DATA;

    while (0 != m_buffer->size()) {
        BufferPeekResult res = m_buffer->peek();
        ASSERT_FALSE(res.err.has_value()) << res.err.value();
        ASSERT_FALSE(res.data.empty());
        ASSERT_EQ(expected_data.substr(0, res.data.size()), (std::string{(char *) res.data.data(), res.data.size()}));
        m_buffer->drain(res.data.size());
        expected_data.erase(0, res.data.size());
    }

    ASSERT_TRUE(expected_data.empty()) << expected_data;
}
// NOLINTEND(bugprone-unchecked-optional-access)
