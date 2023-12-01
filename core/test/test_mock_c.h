#pragma once

#include <any>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

#include <gtest/gtest.h>
#include <magic_enum/magic_enum.hpp>

#include "net/locations_pinger.h"
#include "test_mock_vpn_client.h"
#include "vpn/utils.h"

namespace test_mock {

using LocationsPingerInfo = std::shared_ptr<ag::LocationsPingerInfo>;

enum Idx {
    IDX_LOCATIONS_PINGER_START,
};

struct Info {
    std::vector<std::any> args;
    std::any return_value;
    std::mutex guard;
    bool called = false;
    std::condition_variable call_barrier;

    void reset() {
        this->args.clear();
        this->return_value.reset();
        this->called = false;
    }

    template <typename T>
    T get_arg(size_t idx) {
        return std::any_cast<T>(this->args[idx]);
    }

    template <typename T>
    T get_return_value() {
        return this->return_value.has_value() ? std::any_cast<T>(this->return_value) : T{};
    }

    void notify_called() {
        std::unique_lock l(this->guard);
        this->called = true;
        this->call_barrier.notify_all();
    }

    bool wait_called(std::optional<std::chrono::milliseconds> timeout = std::nullopt) {
        std::unique_lock l(this->guard);
        bool waited = this->call_barrier.wait_for(l, timeout.value_or(std::chrono::seconds(10)), [this]() {
            return this->called;
        });
        this->called = false;
        return waited;
    }
};

} // namespace test_mock

class MockedTest : public testing::Test {
public:
    static std::array<test_mock::Info, magic_enum::enum_count<test_mock::Idx>()> g_infos;

protected:
    void SetUp() override {
    }

    void TearDown() override {
        reset_infos();
        test_mock::g_client.reset();
    }

    static void reset_infos();
};
