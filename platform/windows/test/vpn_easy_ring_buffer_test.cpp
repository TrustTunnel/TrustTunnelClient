#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vpn/trusttunnel/persistent_ring_buffer.h"
#include "vpn/vpn_easy_service.h"

namespace {

std::string temp_file_path() {
    char tmp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_path);
    char tmp_file[MAX_PATH];
    GetTempFileNameA(tmp_path, "rb_", 0, tmp_file);
    return tmp_file;
}

class RingBufferTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_path = temp_file_path();
        std::filesystem::remove(m_path, m_error);
    }

    void TearDown() override {
        std::filesystem::remove(m_path, m_error);
    }

    void write_records(int count) {
        ag::PersistentRingBuffer buffer(m_path);
        for (int i = 0; i < count; ++i) {
            buffer.append("{\"id\":" + std::to_string(i) + "}");
        }
    }

    std::string m_path;
    std::error_code m_error;
};

} // namespace

TEST_F(RingBufferTest, ReadAllEmptyFile) {
    // File doesn't exist yet — read should not crash and not call the callback
    bool called = false;
    vpn_easy_service_read_all_connection_info(
            m_path.c_str(),
            [](void *arg, const char * /*json*/) {
                *static_cast<bool *>(arg) = true;
            },
            &called);
    EXPECT_FALSE(called);
}

TEST_F(RingBufferTest, ReadAllExistingRecords) {
    write_records(5);

    std::vector<std::string> received;
    vpn_easy_service_read_all_connection_info(
            m_path.c_str(),
            [](void *arg, const char *json) {
                static_cast<std::vector<std::string> *>(arg)->emplace_back(json);
            },
            &received);

    ASSERT_EQ(received.size(), 5u);
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(received[i], "{\"id\":" + std::to_string(i) + "}");
    }
}

TEST_F(RingBufferTest, ReadAllCorruptedFileClears) {
    // Write something that isn't a valid ring buffer
    {
        FILE *f = fopen(m_path.c_str(), "wb");
        ASSERT_NE(f, nullptr);
        const char garbage[] = "not a ring buffer";
        fwrite(garbage, 1, sizeof(garbage), f);
        fclose(f);
    }

    bool called = false;
    vpn_easy_service_read_all_connection_info(
            m_path.c_str(),
            [](void *arg, const char * /*json*/) {
                *static_cast<bool *>(arg) = true;
            },
            &called);
    EXPECT_FALSE(called);

    // After clearing, the file should be usable again
    ag::PersistentRingBuffer buffer(m_path);
    EXPECT_TRUE(buffer.append("{\"fresh\":true}"));
    auto result = buffer.read_all();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->records.size(), 1u);
    EXPECT_EQ(result->records[0], "{\"fresh\":true}");
}
