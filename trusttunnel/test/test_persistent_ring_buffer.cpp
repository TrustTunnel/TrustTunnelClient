#include <gtest/gtest.h>

#include <filesystem>

#include "common/file.h"
#include "vpn/platform.h"
#include "vpn/trusttunnel/persistent_ring_buffer.h"

using namespace ag;

static void remove_file_if_exists(const std::string &path) {
    std::error_code error;
    std::filesystem::remove(path, error);
}

static void expect_record_ids(const std::vector<std::string> &records, uint32_t first_id) {
    ASSERT_FALSE(records.empty());
    for (size_t index = 0; index < records.size(); ++index) {
        EXPECT_EQ(records[index], "{\"id\":" + std::to_string(first_id + index) + "}");
    }
}

static void write_legacy_file(const std::string &path) {
    file::Handle fd = file::open(path, file::CREAT | file::TRUNC | file::RDWR);
    ASSERT_NE(fd, file::INVALID_HANDLE) << sys::strerror(sys::last_error());

    constexpr char LEGACY_DATA[] = "legacy";
    ASSERT_EQ(file::write(fd, LEGACY_DATA, sizeof(LEGACY_DATA) - 1), sizeof(LEGACY_DATA) - 1)
            << sys::strerror(sys::last_error());
    file::close(fd);
}

static void corrupt_magic(const std::string &path) {
    file::Handle fd = file::open(path, file::RDWR);
    ASSERT_NE(fd, file::INVALID_HANDLE) << sys::strerror(sys::last_error());

    constexpr uint8_t CORRUPTED_MAGIC[] = {0, 0, 0, 0};
    ASSERT_GE(file::set_position(fd, 0), 0) << sys::strerror(sys::last_error());
    ASSERT_EQ(file::write(fd, CORRUPTED_MAGIC, sizeof(CORRUPTED_MAGIC)), sizeof(CORRUPTED_MAGIC))
            << sys::strerror(sys::last_error());
    file::close(fd);
}

class PersistentRingBufferTest : public testing::Test {
protected:
    std::string path = "./persistent-ring-buffer-test.dat";

    void SetUp() override {
        remove_file_if_exists(path);
    }

    void TearDown() override {
        remove_file_if_exists(path);
    }
};

TEST_F(PersistentRingBufferTest, ReadsNewestRecordsInWriteOrder) {
    PersistentRingBuffer buffer(path);

    ASSERT_TRUE(buffer.append(R"({"id":1})"));
    ASSERT_TRUE(buffer.append(R"({"id":2})"));

    auto result = buffer.read_all();

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->records.size(), 2);
    expect_record_ids(result->records, 1);
}

TEST_F(PersistentRingBufferTest, ClampsStaleCursorToEarliestRetainedRecord) {
    PersistentRingBuffer buffer(path);
    for (uint32_t i = 0; i < PersistentRingBuffer::MAX_RECORDS + 3; ++i) {
        ASSERT_TRUE(buffer.append("{\"id\":" + std::to_string(i) + "}"));
    }

    auto result = buffer.read_since(0);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->records.size(), PersistentRingBuffer::MAX_RECORDS);
    expect_record_ids(result->records, 3);
}

TEST_F(PersistentRingBufferTest, StartupSnapshotReturnsNewestFiveHundredRecords) {
    PersistentRingBuffer buffer(path);
    for (uint32_t i = 0; i < PersistentRingBuffer::MAX_RECORDS + 25; ++i) {
        ASSERT_TRUE(buffer.append("{\"id\":" + std::to_string(i) + "}"));
    }

    auto result = buffer.read_all();

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->records.size(), PersistentRingBuffer::MAX_RECORDS);
    expect_record_ids(result->records, 25);
}

TEST_F(PersistentRingBufferTest, RejectsOversizedRecordWithoutChangingRetainedData) {
    PersistentRingBuffer buffer(path);

    ASSERT_TRUE(buffer.append(R"({"id":1})"));

    std::string oversized(PersistentRingBuffer::MAX_RECORD_BYTES + 1, 'x');
    bool append_ok = buffer.append(oversized);

    ASSERT_FALSE(append_ok);
    auto result = buffer.read_all();

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->records, (std::vector<std::string>{R"({"id":1})"}));
}

TEST_F(PersistentRingBufferTest, ReturnsOnlyUnreadRecordsForIncrementalRead) {
    PersistentRingBuffer buffer(path);

    ASSERT_TRUE(buffer.append(R"({"id":1})"));
    ASSERT_TRUE(buffer.append(R"({"id":2})"));

    auto initial = buffer.read_all();
    ASSERT_TRUE(initial.has_value());
    ASSERT_EQ(initial->next_sequence, 2);

    ASSERT_TRUE(buffer.append(R"({"id":3})"));
    ASSERT_TRUE(buffer.append(R"({"id":4})"));

    auto incremental = buffer.read_since(initial->next_sequence);
    ASSERT_TRUE(incremental.has_value());
    ASSERT_EQ(incremental->records, (std::vector<std::string>{R"({"id":3})", R"({"id":4})"}));
    ASSERT_EQ(incremental->next_sequence, 4);
}

TEST_F(PersistentRingBufferTest, FailsWhenHeaderIsCorrupted) {
    PersistentRingBuffer buffer(path);

    ASSERT_TRUE(buffer.append(R"({"id":1})"));
    corrupt_magic(path);

    ASSERT_FALSE(buffer.append(R"({"id":2})"));
    ASSERT_FALSE(buffer.read_all().has_value());

    ASSERT_TRUE(buffer.clear());
    ASSERT_TRUE(buffer.append(R"({"id":3})"));

    auto result = buffer.read_all();
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->records, (std::vector<std::string>{R"({"id":3})"}));
}

TEST_F(PersistentRingBufferTest, FailsOnIncompatibleLegacyFile) {
    write_legacy_file(path);

    PersistentRingBuffer buffer(path);
    ASSERT_FALSE(buffer.append(R"({"id":1})"));
    ASSERT_FALSE(buffer.read_all().has_value());

    ASSERT_TRUE(buffer.clear());
    ASSERT_TRUE(buffer.append(R"({"id":2})"));

    auto result = buffer.read_all();
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->records, (std::vector<std::string>{R"({"id":2})"}));
}

TEST_F(PersistentRingBufferTest, ClearsBufferFileOnExplicitClear) {
    PersistentRingBuffer buffer(path);

    ASSERT_TRUE(buffer.append(R"({"id":1})"));
    ASSERT_TRUE(std::filesystem::exists(path));
    ASSERT_TRUE(buffer.clear());
    ASSERT_FALSE(std::filesystem::exists(path));

    auto result = buffer.read_all();
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->records.empty());
    ASSERT_EQ(result->next_sequence, 0);
}

TEST_F(PersistentRingBufferTest, WorksWithCustomParameters) {
    PersistentRingBuffer buffer(path, 3, 64);

    ASSERT_TRUE(buffer.append(R"({"id":1})"));
    ASSERT_TRUE(buffer.append(R"({"id":2})"));
    ASSERT_TRUE(buffer.append(R"({"id":3})"));
    ASSERT_TRUE(buffer.append(R"({"id":4})"));

    auto result = buffer.read_all();
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->records.size(), 3);
    expect_record_ids(result->records, 2);
}

TEST_F(PersistentRingBufferTest, TreatsFileAsCorruptedAfterParameterChange) {
    PersistentRingBuffer buffer_v1(path, 10, 128);
    ASSERT_TRUE(buffer_v1.append(R"({"id":1})"));

    PersistentRingBuffer buffer_v2(path, 20, 128);
    ASSERT_FALSE(buffer_v2.append(R"({"id":2})"));
    ASSERT_FALSE(buffer_v2.read_all().has_value());

    ASSERT_TRUE(buffer_v2.clear());
    ASSERT_TRUE(buffer_v2.append(R"({"id":3})"));

    auto result = buffer_v2.read_all();
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->records, (std::vector<std::string>{R"({"id":3})"}));
}