#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vpn/trusttunnel/persistent_ring_buffer.h"
#include "vpn/vpn_easy_service.h"
#include "scoped_file_lock.h"

namespace {

std::wstring temp_file_path() {
    wchar_t tmp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp_path);
    wchar_t tmp_file[MAX_PATH];
    GetTempFileNameW(tmp_path, L"rb_", 0, tmp_file);
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

    std::wstring m_path;
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
        FILE *f = _wfopen(m_path.c_str(), L"wb");
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

// ---------------------------------------------------------------------------
// ScopedFileLock tests
// ---------------------------------------------------------------------------

class ScopedFileLockTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_path = temp_file_path();
        std::filesystem::remove(m_path, m_error);
        // Also clean up any stale lock file
        std::filesystem::remove(std::wstring(m_path) + L".lock", m_error);
    }

    void TearDown() override {
        std::filesystem::remove(m_path, m_error);
        std::filesystem::remove(std::wstring(m_path) + L".lock", m_error);
    }

    std::wstring m_path;
    std::error_code m_error;
};

TEST_F(ScopedFileLockTest, AcquireLockOnNewFile) {
    // Acquiring the lock should succeed even if neither the ring buffer nor the
    // lock file exists yet (the lock file is created automatically).
    ag::vpn_easy::ScopedFileLock lock(m_path);
    EXPECT_TRUE(static_cast<bool>(lock));

    // The lock file should now exist on disk.
    EXPECT_TRUE(std::filesystem::exists(std::wstring(m_path) + L".lock"));
}

TEST_F(ScopedFileLockTest, AcquireLockOnExistingFile) {
    // Create a ring buffer file first, then acquire the lock.
    ag::PersistentRingBuffer buffer(m_path);
    ASSERT_TRUE(buffer.append("{\"test\":1}"));

    ag::vpn_easy::ScopedFileLock lock(m_path);
    EXPECT_TRUE(static_cast<bool>(lock));
}

TEST_F(ScopedFileLockTest, LockReleasedOnDestruction) {
    // Acquire and release a lock, then acquire again — must not deadlock.
    {
        ag::vpn_easy::ScopedFileLock lock(m_path);
        EXPECT_TRUE(static_cast<bool>(lock));
    }
    // After the lock is destroyed, a new lock should be acquired immediately.
    ag::vpn_easy::ScopedFileLock lock2(m_path);
    EXPECT_TRUE(static_cast<bool>(lock2));
}

TEST_F(ScopedFileLockTest, ExclusiveLockBlocksSecondLocker) {
    // Acquire the lock in this thread, then spawn a second thread that tries
    // to acquire the same lock. The second thread should block until the first
    // lock is released.
    auto lock1 = std::make_unique<ag::vpn_easy::ScopedFileLock>(m_path);
    ASSERT_TRUE(static_cast<bool>(*lock1));

    std::atomic<bool> second_acquired{false};
    std::thread blocker([&] {
        ag::vpn_easy::ScopedFileLock lock2(m_path);
        second_acquired.store(static_cast<bool>(lock2), std::memory_order_release);
    });

    // Give the second thread time to attempt acquiring the lock.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    // The second thread should still be blocked.
    EXPECT_FALSE(second_acquired.load(std::memory_order_acquire));

    // Release the first lock; the second thread should now proceed.
    lock1.reset();
    blocker.join();
    EXPECT_TRUE(second_acquired.load(std::memory_order_acquire));
}

TEST_F(ScopedFileLockTest, LockOnInvalidPath) {
    // '?' is a reserved character in Windows paths, so CreateFileW always
    // rejects it with ERROR_INVALID_NAME. This makes the negative test
    // deterministic, independent of which drive letters are mounted.
    ag::vpn_easy::ScopedFileLock lock(L"?:\\nonexistent\\deep\\path\\buffer.dat");
    EXPECT_FALSE(static_cast<bool>(lock));
}

TEST_F(ScopedFileLockTest, LockAllowsReadAndWrite) {
    // Acquire the lock, then read/write the ring buffer while holding it.
    ag::PersistentRingBuffer buffer(m_path);
    ASSERT_TRUE(buffer.append("{\"locked_write\":true}"));

    ag::vpn_easy::ScopedFileLock lock(m_path);
    ASSERT_TRUE(static_cast<bool>(lock));

    auto result = buffer.read_all();
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->records.size(), 1u);
    EXPECT_EQ(result->records[0], "{\"locked_write\":true}");
}

// ---------------------------------------------------------------------------
// vpn_easy_service_read_all_connection_info edge cases
// ---------------------------------------------------------------------------

TEST_F(RingBufferTest, ReadAllNullPath) {
    // Passing a null path should not crash.
    bool called = false;
    vpn_easy_service_read_all_connection_info(
            nullptr,
            [](void *arg, const char *) {
                *static_cast<bool *>(arg) = true;
            },
            &called);
    EXPECT_FALSE(called);
}

TEST_F(RingBufferTest, ReadAllNullCallback) {
    // Passing a null callback should not crash.
    write_records(3);
    vpn_easy_service_read_all_connection_info(m_path.c_str(), nullptr, nullptr);
    // No crash is the assertion.
}

TEST_F(RingBufferTest, ReadAllSingleRecord) {
    ag::PersistentRingBuffer buffer(m_path);
    ASSERT_TRUE(buffer.append("{\"only\":true}"));

    std::vector<std::string> received;
    vpn_easy_service_read_all_connection_info(
            m_path.c_str(),
            [](void *arg, const char *json) {
                static_cast<std::vector<std::string> *>(arg)->emplace_back(json);
            },
            &received);

    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(received[0], "{\"only\":true}");
}

TEST_F(RingBufferTest, ReadAllManyRecords) {
    // Write multiple records and verify that read-all returns them in order.
    constexpr int COUNT = 50;
    write_records(COUNT);

    std::vector<std::string> received;
    vpn_easy_service_read_all_connection_info(
            m_path.c_str(),
            [](void *arg, const char *json) {
                static_cast<std::vector<std::string> *>(arg)->emplace_back(json);
            },
            &received);

    ASSERT_EQ(received.size(), static_cast<size_t>(COUNT));
    for (int i = 0; i < COUNT; ++i) {
        EXPECT_EQ(received[i], "{\"id\":" + std::to_string(i) + "}");
    }
}

TEST_F(RingBufferTest, ReadAllOverlap) {
    // Check the ring buffer override behavior.
    constexpr int COUNT = 510;
    constexpr int MAX_COUNT = 500; // ag::PersistentRingBuffer::MAX_RECORDS
    write_records(COUNT);

    std::vector<std::string> received;
    vpn_easy_service_read_all_connection_info(
            m_path.c_str(),
            [](void *arg, const char *json) {
                static_cast<std::vector<std::string> *>(arg)->emplace_back(json);
            },
            &received);

    ASSERT_EQ(received.size(), static_cast<size_t>(MAX_COUNT));
    for (int i = 0; i < MAX_COUNT; ++i) {
        // `i + 10` because the ring buffer should have overwritten the first 10 records (COUNT - MAX_COUNT = 10)
        EXPECT_EQ(received[i], "{\"id\":" + std::to_string(i + 10) + "}");
    }
}

TEST_F(RingBufferTest, ReadAllEmptyRingBufferFile) {
    // Create a valid but empty ring buffer (no records appended).
    ag::PersistentRingBuffer buffer(m_path);

    bool called = false;
    vpn_easy_service_read_all_connection_info(
            m_path.c_str(),
            [](void *arg, const char *) {
                *static_cast<bool *>(arg) = true;
            },
            &called);
    EXPECT_FALSE(called);
}

TEST_F(RingBufferTest, ReadAllCallbackReceivesNullTerminatedJson) {
    ag::PersistentRingBuffer buffer(m_path);
    ASSERT_TRUE(buffer.append("{\"key\":\"value\"}"));

    vpn_easy_service_read_all_connection_info(
            m_path.c_str(),
            [](void * /*arg*/, const char *json) {
                // The json pointer must be null-terminated so that strlen works.
                ASSERT_NE(json, nullptr);
                std::string str(json);
                EXPECT_EQ(str, "{\"key\":\"value\"}");
            },
            nullptr);
}

TEST_F(RingBufferTest, ReadAllRecordsPreservedAfterRead) {
    // Reading all connection info should not modify the ring buffer.
    write_records(3);

    vpn_easy_service_read_all_connection_info(m_path.c_str(), [](void *, const char *) {}, nullptr);

    // The records should still be present after the read.
    ag::PersistentRingBuffer buffer(m_path);
    auto result = buffer.read_all();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->records.size(), 3u);
}
