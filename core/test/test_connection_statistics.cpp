#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "connection_statistics.h"

class ConnectionStatisticsMonitor : public ::testing::Test {
protected:
    std::vector<ag::ConnectionStatistics> m_stats;
    std::thread m_loop_thread;
    ag::UniquePtr<ag::VpnEventLoop, &ag::vpn_event_loop_destroy> m_event_loop{ag::vpn_event_loop_create()};
    ag::ConnectionStatisticsMonitor::Handler m_handler = [this](ag::ConnectionStatistics x) {
        m_stats.push_back(x);
    };

    void SetUp() override {
        m_loop_thread = std::thread([this]() {
            ag::vpn_event_loop_run(m_event_loop.get());
        });
    }

    void TearDown() override {
        ag::vpn_event_loop_stop(m_event_loop.get());
        if (m_loop_thread.joinable()) {
            m_loop_thread.join();
        }
    }
};

TEST_F(ConnectionStatisticsMonitor, DontRaiseThrottlingTrafficThresholdReached) {
    static constexpr uint64_t THRESHOLD = 42;
    static constexpr uint64_t ID = 21;
    static constexpr auto THROTTLING_PERIOD = ag::Millis{1000000};

    ag::ConnectionStatisticsMonitor monitor{m_event_loop.get(), m_handler, THROTTLING_PERIOD, THRESHOLD};
    monitor.register_conn(ID);
    monitor.update_upload(ID, 2 * THRESHOLD);
    monitor.update_download(ID, 2 * THRESHOLD);
    ASSERT_EQ(m_stats.size(), 0);
}

TEST_F(ConnectionStatisticsMonitor, DontRaiseNoThrottlingTrafficThresholdNotReached) {
    static constexpr uint64_t THRESHOLD = 42;
    static constexpr uint64_t INC = THRESHOLD - 1;
    static constexpr uint64_t ID = 21;
    static constexpr auto THROTTLING_PERIOD = ag::Millis{100};

    ag::ConnectionStatisticsMonitor monitor{m_event_loop.get(), m_handler, THROTTLING_PERIOD, THRESHOLD};
    monitor.register_conn(ID);
    monitor.update_upload(ID, INC);
    monitor.update_download(ID, INC);
    ASSERT_EQ(m_stats.size(), 0);

    std::this_thread::sleep_for(2 * THROTTLING_PERIOD);

    ASSERT_EQ(m_stats.size(), 0);
}

TEST_F(ConnectionStatisticsMonitor, RaiseTrafficThresholdReached) {
    static constexpr uint64_t THRESHOLD = 42;
    static constexpr uint64_t ID = 21;
    static constexpr auto THROTTLING_PERIOD = ag::Millis{100};

    ag::ConnectionStatisticsMonitor monitor{m_event_loop.get(), m_handler, THROTTLING_PERIOD, THRESHOLD};
    monitor.register_conn(ID);
    monitor.update_upload(ID, THRESHOLD);
    monitor.update_download(ID, THRESHOLD);
    ASSERT_EQ(m_stats.size(), 0);

    std::this_thread::sleep_for(2 * THROTTLING_PERIOD);

    ASSERT_EQ(m_stats.size(), 0);
    monitor.update_upload(ID, 1);
    ASSERT_EQ(m_stats.size(), 1);
    ASSERT_EQ(m_stats[0].id, ID);
    ASSERT_EQ(m_stats[0].upload, THRESHOLD + 1);
    ASSERT_EQ(m_stats[0].download, THRESHOLD);
}

TEST_F(ConnectionStatisticsMonitor, RaiseMultiple) {
    static constexpr uint64_t THRESHOLD = 42;
    static constexpr uint64_t ID = 21;
    static constexpr auto THROTTLING_PERIOD = ag::Millis{50};

    ag::ConnectionStatisticsMonitor monitor{m_event_loop.get(), m_handler, THROTTLING_PERIOD, THRESHOLD};
    monitor.register_conn(ID);
    monitor.update_upload(ID, THRESHOLD);
    monitor.update_download(ID, THRESHOLD);

    std::this_thread::sleep_for(2 * THROTTLING_PERIOD);

    ASSERT_EQ(m_stats.size(), 0);
    monitor.update_upload(ID, 1);
    ASSERT_EQ(m_stats.size(), 1);
    ASSERT_EQ(m_stats[0].id, ID);
    ASSERT_EQ(m_stats[0].upload, THRESHOLD + 1);
    ASSERT_EQ(m_stats[0].download, THRESHOLD);

    monitor.update_upload(ID, THRESHOLD);
    monitor.update_download(ID, THRESHOLD);
    ASSERT_EQ(m_stats.size(), 1);

    std::this_thread::sleep_for(2 * THROTTLING_PERIOD);

    ASSERT_EQ(m_stats.size(), 1);
    monitor.update_upload(ID, 1);
    ASSERT_EQ(m_stats.size(), 2);
    ASSERT_EQ(m_stats[1].id, ID);
    ASSERT_EQ(m_stats[1].upload, THRESHOLD + 1);
    ASSERT_EQ(m_stats[1].download, THRESHOLD);
}

TEST_F(ConnectionStatisticsMonitor, DontRaiseOnUnregister) {
    static constexpr uint64_t THRESHOLD = 42;
    static constexpr uint64_t INC = THRESHOLD - 1;
    static constexpr uint64_t ID = 21;
    static constexpr auto THROTTLING_PERIOD = ag::Millis{100};

    ag::ConnectionStatisticsMonitor monitor{m_event_loop.get(), m_handler, THROTTLING_PERIOD, THRESHOLD};
    monitor.register_conn(ID);
    monitor.update_upload(ID, INC);
    monitor.update_download(ID, INC);
    ASSERT_EQ(m_stats.size(), 0);
    monitor.unregister_conn(ID, /*do_report*/ false);

    std::this_thread::sleep_for(2 * THROTTLING_PERIOD);

    ASSERT_EQ(m_stats.size(), 0);
}

TEST_F(ConnectionStatisticsMonitor, RaiseOnUnregister) {
    static constexpr uint64_t THRESHOLD = 42;
    static constexpr uint64_t INC = THRESHOLD - 1;
    static constexpr uint64_t ID = 21;
    static constexpr auto THROTTLING_PERIOD = ag::Millis{100};

    ag::ConnectionStatisticsMonitor monitor{m_event_loop.get(), m_handler, THROTTLING_PERIOD, THRESHOLD};
    monitor.register_conn(ID);
    monitor.update_upload(ID, INC);
    monitor.update_download(ID, INC);
    ASSERT_EQ(m_stats.size(), 0);
    monitor.unregister_conn(ID, /*do_report*/ true);

    std::this_thread::sleep_for(2 * THROTTLING_PERIOD);

    ASSERT_EQ(m_stats.size(), 1);
    ASSERT_EQ(m_stats[0].id, ID);
    ASSERT_EQ(m_stats[0].upload, INC);
    ASSERT_EQ(m_stats[0].download, INC);
}
