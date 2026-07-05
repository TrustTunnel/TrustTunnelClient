#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "common/file.h"
#include "common/utils.h"
#include "vpn/internal/utils.h"
#include "vpn/utils.h"

using namespace ag;

class TunnelAddressTest : public testing::TestWithParam<std::pair<TunnelAddress, TunnelAddress>> {
protected:
};

class Equal : public TunnelAddressTest {};
TEST_P(Equal, Test) {
    const auto &param = GetParam();
    ASSERT_EQ(param.first, param.second);
}

static const std::pair<TunnelAddress, TunnelAddress> EQUAL_ADDRS_SAMPLES[] = {
        {NamePort{"example.org", 80}, NamePort{"example.org", 80}},
        {SocketAddress("1.1.1.1:1"), SocketAddress("1.1.1.1:1")},
        {SocketAddress("1.1.1.1"), SocketAddress("1.1.1.1")},
        {SocketAddress("[::1]:1"), SocketAddress("[::1]:1")},
        {SocketAddress("::1"), SocketAddress("::1")},
};
INSTANTIATE_TEST_SUITE_P(TunnelAddress, Equal, testing::ValuesIn(EQUAL_ADDRS_SAMPLES));

class NotEqual : public TunnelAddressTest {};
TEST_P(NotEqual, Test) {
    const auto &param = GetParam();
    ASSERT_NE(param.first, param.second);
}

static const std::pair<TunnelAddress, TunnelAddress> NOT_EQUAL_ADDRS_SAMPLES[] = {
        {NamePort{"example.org", 80}, NamePort{"example.org", 0}},
        {NamePort{"example.org", 80}, NamePort{"example.com", 80}},
        {NamePort{"example.org", 80}, NamePort{"Example.org", 80}},
        {SocketAddress("1.1.1.1:1"), SocketAddress("1.1.1.1:0")},
        {SocketAddress("1.1.1.1:1"), SocketAddress("1.1.1.11:1")},
        {SocketAddress("[::1]:1"), SocketAddress("[::1]:11")},
        {SocketAddress("[::1]:1"), SocketAddress("[::2]:1")},
        {SocketAddress("::1"), SocketAddress("::2")},
};
INSTANTIATE_TEST_SUITE_P(TunnelAddressTest, NotEqual, testing::ValuesIn(NOT_EQUAL_ADDRS_SAMPLES));

class CleanUpFiles : public ::testing::Test {
protected:
    static constexpr const char *DIR = "./hopefully_nonexisting_dir";
    std::error_code fs_err;

    void SetUp() override {
        ASSERT_FALSE(fs::exists(DIR, fs_err));
        ASSERT_FALSE(fs_err) << fs_err.message();
    }

    void TearDown() override {
        fs::remove_all(DIR, fs_err);
        ASSERT_FALSE(fs_err) << fs_err.message();
    }
};

TEST_F(CleanUpFiles, NonExistingDirectory) {
    // just check it does not crash
    clean_up_buffer_files(DIR);
}

static void create_buffer_file(const std::string &dir, const std::string &name) {
    file::Handle fd = file::open(AG_FMT("{}/{}", dir, name), file::CREAT);
    ASSERT_NE(fd, file::INVALID_HANDLE) << sys::strerror(sys::last_error());
    file::close(fd);
}

TEST_F(CleanUpFiles, Test) {
    fs::create_directory(DIR, fs_err);
    ASSERT_FALSE(fs_err) << fs_err.message();

    std::vector<std::string> file_names;
    for (uint64_t i = 0; i < 10; ++i) {
        file_names.emplace_back(str_format(CONN_BUFFER_FILE_NAME_FMT, i, i + 1));
    }

    for (const std::string &fn : file_names) {
        ASSERT_NO_FATAL_FAILURE(create_buffer_file(DIR, fn));
    }

    clean_up_buffer_files(DIR);

    for (const std::string &fn : file_names) {
        ASSERT_FALSE(fs::exists(fs::path(DIR) / fn, fs_err));
        ASSERT_FALSE(fs_err) << fs_err.message();
    }
}
