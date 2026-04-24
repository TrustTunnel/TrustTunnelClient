#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "common/logger.h"
#include "vpn/internal/wire_utils.h"

#include "vpn_easy_pipe.h"

using namespace ag::vpn_easy;
using namespace std::chrono_literals;

namespace {

constexpr auto TEST_TIMEOUT = std::chrono::seconds(5);
constexpr auto JOIN_TIMEOUT = std::chrono::seconds(5);
// Mirrors PipeEndpoint::MAX_MESSAGE_SIZE (private). If that changes, update here.
constexpr size_t MAX_MESSAGE_SIZE = 16 * 1024;
constexpr size_t WIRE_HEADER_SIZE = 8;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::wstring unique_pipe_name() {
    static std::atomic<uint64_t> counter{0};
    auto pid = static_cast<uint64_t>(GetCurrentProcessId());
    auto n = counter.fetch_add(1, std::memory_order_relaxed);
    return L"\\\\.\\pipe\\agvpn_pipe_test_" + std::to_wstring(pid) + L"_" + std::to_wstring(n);
}

std::vector<uint8_t> make_framed(uint32_t what, std::span<const uint8_t> payload) {
    std::vector<uint8_t> ret(WIRE_HEADER_SIZE + payload.size());
    ag::wire_utils::Writer w{{ret.data(), ret.size()}};
    w.put_u32(what);
    w.put_u32(static_cast<uint32_t>(payload.size()));
    w.put_data({payload.data(), payload.size()});
    return ret;
}

// Build a header whose advertised length differs from the actual payload size; used by the
// oversized-message test.
std::vector<uint8_t> make_framed_with_advertised_len(uint32_t what, uint32_t advertised_len) {
    std::vector<uint8_t> ret(WIRE_HEADER_SIZE);
    ag::wire_utils::Writer w{{ret.data(), ret.size()}};
    w.put_u32(what);
    w.put_u32(advertised_len);
    return ret;
}

struct ReceivedMessage {
    VpnEasyServiceMessageType what;
    std::vector<uint8_t> payload;
};

// Thread-safe receiver of messages delivered via PipeEndpoint::Handler.
class MessageCollector {
public:
    PipeEndpoint::Handler make_handler() {
        return [this](VpnEasyServiceMessageType what, ag::Uint8View data) {
            std::scoped_lock l{m_lock};
            m_messages.push_back({what, std::vector<uint8_t>(data.begin(), data.end())});
            m_cv.notify_all();
        };
    }

    bool wait_for_count(size_t n, std::chrono::milliseconds timeout) {
        std::unique_lock l{m_lock};
        return m_cv.wait_for(l, timeout, [&] { return m_messages.size() >= n; });
    }

    std::vector<ReceivedMessage> snapshot() {
        std::scoped_lock l{m_lock};
        return m_messages;
    }

    size_t count() {
        std::scoped_lock l{m_lock};
        return m_messages.size();
    }

private:
    std::mutex m_lock;
    std::condition_variable m_cv;
    std::vector<ReceivedMessage> m_messages;
};

// RAII Win32 HANDLE wrapper.
class Handle {
public:
    Handle() = default;
    explicit Handle(HANDLE h) : m_h(h) {}
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&o) noexcept : m_h(std::exchange(o.m_h, INVALID_HANDLE_VALUE)) {}
    Handle &operator=(Handle &&o) noexcept {
        reset();
        m_h = std::exchange(o.m_h, INVALID_HANDLE_VALUE);
        return *this;
    }
    ~Handle() {
        reset();
    }

    void reset() {
        if (m_h != nullptr && m_h != INVALID_HANDLE_VALUE) {
            CloseHandle(m_h);
        }
        m_h = INVALID_HANDLE_VALUE;
    }

    HANDLE get() const {
        return m_h;
    }
    explicit operator bool() const {
        return m_h != nullptr && m_h != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE m_h = INVALID_HANDLE_VALUE;
};

// Open a raw (overlapped) client connection to a server pipe, retrying until `timeout` elapses.
Handle open_raw_client(const std::wstring &name, std::chrono::milliseconds timeout = TEST_TIMEOUT) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            return Handle{h};
        }
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PIPE_BUSY) {
            return Handle{};
        }
        if (std::chrono::steady_clock::now() > deadline) {
            return Handle{};
        }
        std::this_thread::sleep_for(10ms);
    }
}

// Synchronously write `data` to an overlapped handle.
bool write_all(HANDLE h, std::span<const uint8_t> data) {
    OVERLAPPED ol{};
    Handle ev{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    ol.hEvent = ev.get();
    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, &ol);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(h, &ol, &written, TRUE);
    }
    return ok && written == data.size();
}

// Read exactly `buf.size()` bytes from an overlapped handle, with a deadline.
bool read_exact(HANDLE h, std::span<uint8_t> buf, std::chrono::milliseconds timeout) {
    Handle ev{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    OVERLAPPED ol{};
    ol.hEvent = ev.get();
    size_t got = 0;
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (got < buf.size()) {
        ResetEvent(ol.hEvent);
        DWORD n = 0;
        BOOL ok = ReadFile(h, buf.data() + got, static_cast<DWORD>(buf.size() - got), &n, &ol);
        if (!ok) {
            DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) {
                return false;
            }
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                CancelIoEx(h, &ol);
                GetOverlappedResult(h, &ol, &n, TRUE);
                return false;
            }
            auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            DWORD w = WaitForSingleObject(ol.hEvent, static_cast<DWORD>(wait_ms));
            if (w != WAIT_OBJECT_0) {
                CancelIoEx(h, &ol);
                GetOverlappedResult(h, &ol, &n, TRUE);
                return false;
            }
            if (!GetOverlappedResult(h, &ol, &n, FALSE)) {
                return false;
            }
        }
        if (n == 0) {
            return false; // EOF
        }
        got += n;
    }
    return true;
}

bool read_framed_message(HANDLE h, ReceivedMessage &out, std::chrono::milliseconds timeout) {
    auto t0 = std::chrono::steady_clock::now();
    uint8_t header[WIRE_HEADER_SIZE];
    if (!read_exact(h, {header, WIRE_HEADER_SIZE}, timeout)) {
        return false;
    }
    ag::wire_utils::Reader r{{header, WIRE_HEADER_SIZE}};
    auto what = r.get_u32();
    auto len = r.get_u32();
    if (!what.has_value() || !len.has_value()) {
        return false;
    }
    out.what = static_cast<VpnEasyServiceMessageType>(*what);
    out.payload.assign(*len, 0);
    if (*len == 0) {
        return true;
    }
    auto remaining = timeout - (std::chrono::steady_clock::now() - t0);
    if (remaining < 0ms) {
        remaining = 0ms;
    }
    return read_exact(h, {out.payload.data(), out.payload.size()},
            std::chrono::duration_cast<std::chrono::milliseconds>(remaining));
}

// Probe whether the server-side has dropped the connection: any IO failure / EOF within the
// timeout is treated as "peer is gone".
bool wait_for_peer_disconnect(HANDLE h, std::chrono::milliseconds timeout) {
    uint8_t byte = 0;
    return !read_exact(h, {&byte, 1}, timeout);
}

// RAII wrapper for a `loop()` invocation on a detached worker thread. The destructor signals
// the bound stop event to ask the loop to exit, then returns immediately without joining; the
// detached thread is left to wind down on its own.
//
// Rationale: the test fixture must remain responsive even if `loop()` itself is buggy and never
// observes the stop event. By detaching, the main thread (and the rest of the test suite) can
// always make progress; an actual `loop()` hang manifests as a test failure (because
// `wait_for(JOIN_TIMEOUT)` returns `timeout`) rather than as a deadlocked test process.
//
// CAVEAT: if `loop()` truly fails to exit, the detached thread will outlive the test's local
// `PipeServer`/`PipeClient`, and continued use of those references inside the loop is undefined
// behavior. A hung `loop()` is a real implementation bug that must be diagnosed and fixed; this
// wrapper just keeps the test harness alive long enough to report it.
class LoopRunner {
public:
    template <typename F>
    LoopRunner(HANDLE stop_event, F &&f) : m_stop_event{stop_event}, m_state{std::make_shared<State>()} {
        auto state = m_state;
        std::thread([state, fn = std::forward<F>(f)]() mutable {
            bool result = fn();
            std::scoped_lock l{state->lock};
            state->result = result;
            state->done = true;
            state->cv.notify_all();
        }).detach();
    }

    LoopRunner(const LoopRunner &) = delete;
    LoopRunner &operator=(const LoopRunner &) = delete;

    ~LoopRunner() {
        if (m_stop_event != nullptr) {
            SetEvent(m_stop_event);
        }
        // Intentionally no join: see class-level comment.
    }

    // Wait up to `t` for `loop()` to return. Returns the loop's return value if it completed
    // within the timeout, or `std::nullopt` if the timeout was reached.
    std::optional<bool> wait_for(std::chrono::milliseconds t) {
        std::unique_lock l{m_state->lock};
        if (!m_state->cv.wait_for(l, t, [&] { return m_state->done; })) {
            return std::nullopt;
        }
        return *m_state->result;
    }

private:
    struct State {
        std::mutex lock;
        std::condition_variable cv;
        bool done = false;
        std::optional<bool> result;
    };

    HANDLE m_stop_event = nullptr;
    std::shared_ptr<State> m_state;
};

class PipeTest : public testing::Test {
protected:
    PipeTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_DEBUG);
        m_stop_event = Handle{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        m_pipe_name = unique_pipe_name();
    }

    void signal_stop() {
        SetEvent(m_stop_event.get());
    }

    Handle m_stop_event;
    std::wstring m_pipe_name;
};

} // namespace

// ---------------------------------------------------------------------------
// PipeServer tests
// ---------------------------------------------------------------------------

TEST_F(PipeTest, ServerLoopFailsImmediately_OnInvalidPipeName) {
    // An empty pipe name causes CreateNamedPipeW to fail; loop() must refuse to start.
    MessageCollector collector;
    PipeServer server{L"", m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};
    auto loop_result = runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(loop_result);
    EXPECT_FALSE(*loop_result);
}

TEST_F(PipeTest, ServerStopEventCausesGracefulExit_NoClientEverConnects) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    // Give the server a moment to post the overlapped ConnectNamedPipe.
    std::this_thread::sleep_for(50ms);
    signal_stop();

    auto loop_result = runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(loop_result);
    EXPECT_TRUE(*loop_result);
    EXPECT_EQ(collector.count(), 0u);
}

TEST_F(PipeTest, ServerReceivesSingleFramedMessage) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);

    const std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    auto frame = make_framed(VPN_EASY_SVC_MSG_START, payload);
    ASSERT_TRUE(write_all(client.get(), frame));

    ASSERT_TRUE(collector.wait_for_count(1, TEST_TIMEOUT));
    auto msgs = collector.snapshot();
    ASSERT_EQ(msgs.size(), 1u);
    EXPECT_EQ(msgs[0].what, VPN_EASY_SVC_MSG_START);
    EXPECT_EQ(msgs[0].payload, payload);

    signal_stop();
    auto loop_result = runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(loop_result);
    EXPECT_TRUE(*loop_result);
}

TEST_F(PipeTest, ServerReceivesMultipleConcatenatedMessages) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);

    // Three messages back-to-back in a single write.
    std::vector<uint8_t> combined;
    auto append = [&](uint32_t what, const std::vector<uint8_t> &p) {
        auto f = make_framed(what, p);
        combined.insert(combined.end(), f.begin(), f.end());
    };
    append(VPN_EASY_SVC_MSG_START, {});
    append(VPN_EASY_SVC_MSG_STOP, {1, 2, 3});
    append(VPN_EASY_SVC_MSG_STATE_CHANGED, {0xFF, 0xEE});
    ASSERT_TRUE(write_all(client.get(), combined));

    ASSERT_TRUE(collector.wait_for_count(3, TEST_TIMEOUT));
    auto msgs = collector.snapshot();
    ASSERT_EQ(msgs.size(), 3u);
    EXPECT_EQ(msgs[0].what, VPN_EASY_SVC_MSG_START);
    EXPECT_TRUE(msgs[0].payload.empty());
    EXPECT_EQ(msgs[1].what, VPN_EASY_SVC_MSG_STOP);
    EXPECT_EQ(msgs[1].payload, (std::vector<uint8_t>{1, 2, 3}));
    EXPECT_EQ(msgs[2].what, VPN_EASY_SVC_MSG_STATE_CHANGED);
    EXPECT_EQ(msgs[2].payload, (std::vector<uint8_t>{0xFF, 0xEE}));

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerReassemblesMessageSplitAcrossWrites) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);

    std::vector<uint8_t> payload(128);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>(i);
    }
    auto frame = make_framed(VPN_EASY_SVC_MSG_CONNECTION_INFO, payload);

    // Header alone, then half the payload, then the rest. The brief sleeps make the test
    // deterministic about reassembly across multiple ReadFile completions.
    ASSERT_TRUE(write_all(client.get(), {frame.data(), WIRE_HEADER_SIZE}));
    std::this_thread::sleep_for(50ms);
    size_t half = payload.size() / 2;
    ASSERT_TRUE(write_all(client.get(), {frame.data() + WIRE_HEADER_SIZE, half}));
    std::this_thread::sleep_for(50ms);
    ASSERT_TRUE(
            write_all(client.get(), {frame.data() + WIRE_HEADER_SIZE + half, payload.size() - half}));

    ASSERT_TRUE(collector.wait_for_count(1, TEST_TIMEOUT));
    auto msgs = collector.snapshot();
    ASSERT_EQ(msgs.size(), 1u);
    EXPECT_EQ(msgs[0].what, VPN_EASY_SVC_MSG_CONNECTION_INFO);
    EXPECT_EQ(msgs[0].payload, payload);

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerReceivesAllMessages_WhenReadFileCompletesSynchronously) {
    // Regression: previously, when ReadFile completed synchronously, start_read() returned
    // without arming the next read or waking the loop, so subsequent incoming bytes were never
    // observed. To exercise the sync-completion path we use a synchronous (non-overlapped) raw
    // client and write many small messages before the server gets a chance to post its first
    // overlapped ReadFile, so that the data is already buffered in the kernel and ReadFile
    // returns synchronously.
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};

    // Open the synchronous client BEFORE spawning the loop, so the server's ConnectNamedPipe
    // returns ERROR_PIPE_CONNECTED on the very first iteration and the kernel pipe buffer is
    // already pre-filled when the first ReadFile is issued.
    Handle client{CreateFileW(m_pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, 0 /* not FILE_FLAG_OVERLAPPED: synchronous writes */, nullptr)};
    ASSERT_TRUE(client);

    constexpr int MESSAGE_COUNT = 100;
    for (int i = 0; i < MESSAGE_COUNT; ++i) {
        uint8_t payload[2] = {static_cast<uint8_t>(i >> 8), static_cast<uint8_t>(i & 0xFF)};
        auto frame = make_framed(VPN_EASY_SVC_MSG_STATE_CHANGED, payload);
        DWORD written = 0;
        ASSERT_TRUE(WriteFile(client.get(), frame.data(), static_cast<DWORD>(frame.size()), &written, nullptr));
        ASSERT_EQ(written, frame.size());
    }

    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    ASSERT_TRUE(collector.wait_for_count(MESSAGE_COUNT, TEST_TIMEOUT));
    auto msgs = collector.snapshot();
    ASSERT_EQ(msgs.size(), static_cast<size_t>(MESSAGE_COUNT));
    for (int i = 0; i < MESSAGE_COUNT; ++i) {
        ASSERT_EQ(msgs[i].payload.size(), 2u);
        EXPECT_EQ((msgs[i].payload[0] << 8) | msgs[i].payload[1], i) << "at index " << i;
    }

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerAcceptsMaxSizedMessage) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);

    std::vector<uint8_t> payload(MAX_MESSAGE_SIZE, 0xAB);
    auto frame = make_framed(VPN_EASY_SVC_MSG_CONNECTION_INFO, payload);
    ASSERT_TRUE(write_all(client.get(), frame));

    ASSERT_TRUE(collector.wait_for_count(1, TEST_TIMEOUT));
    auto msgs = collector.snapshot();
    ASSERT_EQ(msgs.size(), 1u);
    EXPECT_EQ(msgs[0].payload.size(), MAX_MESSAGE_SIZE);

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerDropsConnectionAndReconnects_OnOversizedMessage) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    // First connection: send an oversized header; expect the server to drop us.
    {
        Handle client = open_raw_client(m_pipe_name);
        ASSERT_TRUE(client);
        auto frame = make_framed_with_advertised_len(
                VPN_EASY_SVC_MSG_START, static_cast<uint32_t>(MAX_MESSAGE_SIZE + 1));
        ASSERT_TRUE(write_all(client.get(), frame));
        EXPECT_TRUE(wait_for_peer_disconnect(client.get(), TEST_TIMEOUT));
    }

    // Second connection: the server should have reconnected and accept fresh traffic.
    {
        Handle client = open_raw_client(m_pipe_name);
        ASSERT_TRUE(client);
        const std::vector<uint8_t> payload = {0x42};
        auto frame = make_framed(VPN_EASY_SVC_MSG_START, payload);
        ASSERT_TRUE(write_all(client.get(), frame));
        ASSERT_TRUE(collector.wait_for_count(1, TEST_TIMEOUT));
        auto msgs = collector.snapshot();
        ASSERT_EQ(msgs.size(), 1u);
        EXPECT_EQ(msgs[0].payload, payload);
    }

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerSendDeliversMessageToClient) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);
    std::this_thread::sleep_for(50ms); // Let the server observe the connection.

    const std::vector<uint8_t> payload = {1, 2, 3, 4, 5};
    server.send(VPN_EASY_SVC_MSG_STATE_CHANGED, {payload.data(), payload.size()});

    ReceivedMessage rx{};
    ASSERT_TRUE(read_framed_message(client.get(), rx, TEST_TIMEOUT));
    EXPECT_EQ(rx.what, VPN_EASY_SVC_MSG_STATE_CHANGED);
    EXPECT_EQ(rx.payload, payload);

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerSendDropsMessage_WhenNoPeerConnected) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    // Send a few messages with no peer connected; they must be dropped.
    const std::vector<uint8_t> dropped_payload = {0xAA};
    for (int i = 0; i < 5; ++i) {
        server.send(VPN_EASY_SVC_MSG_STATE_CHANGED, {dropped_payload.data(), dropped_payload.size()});
    }
    std::this_thread::sleep_for(50ms);

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);
    std::this_thread::sleep_for(50ms);

    // Send a sentinel via the live connection. Only the sentinel must arrive.
    const std::vector<uint8_t> sentinel_payload = {0x55};
    server.send(VPN_EASY_SVC_MSG_CONNECTION_INFO, {sentinel_payload.data(), sentinel_payload.size()});

    ReceivedMessage rx{};
    ASSERT_TRUE(read_framed_message(client.get(), rx, TEST_TIMEOUT));
    EXPECT_EQ(rx.what, VPN_EASY_SVC_MSG_CONNECTION_INFO);
    EXPECT_EQ(rx.payload, sentinel_payload);

    // No further messages should arrive (the dropped ones must not have been queued).
    ReceivedMessage extra{};
    EXPECT_FALSE(read_framed_message(client.get(), extra, 200ms));

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerSendIsThreadSafe) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);
    std::this_thread::sleep_for(50ms);

    constexpr int THREAD_COUNT = 4;
    constexpr int PER_THREAD = 25;
    std::vector<std::thread> senders;
    senders.reserve(THREAD_COUNT);
    for (int t = 0; t < THREAD_COUNT; ++t) {
        senders.emplace_back([&, t] {
            for (int i = 0; i < PER_THREAD; ++i) {
                uint8_t payload[2] = {static_cast<uint8_t>(t), static_cast<uint8_t>(i)};
                server.send(VPN_EASY_SVC_MSG_STATE_CHANGED, {payload, 2});
            }
        });
    }
    for (auto &th : senders) {
        th.join();
    }

    // Read all messages back. Per-thread submission order must be preserved (within each
    // thread's stream); messages from different threads may interleave arbitrarily.
    std::vector<int> last_seen(THREAD_COUNT, -1);
    for (int i = 0; i < THREAD_COUNT * PER_THREAD; ++i) {
        ReceivedMessage rx{};
        ASSERT_TRUE(read_framed_message(client.get(), rx, TEST_TIMEOUT)) << "at message " << i;
        ASSERT_EQ(rx.payload.size(), 2u);
        int t = rx.payload[0];
        int idx = rx.payload[1];
        ASSERT_GE(t, 0);
        ASSERT_LT(t, THREAD_COUNT);
        EXPECT_GT(idx, last_seen[t]) << "messages from thread " << t << " out of order";
        last_seen[t] = idx;
    }

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerHandlerCanCallSend) {
    // Handler echoes any incoming message back as VPN_EASY_SVC_MSG_STATE_CHANGED, exercising
    // send() being called from the loop's own thread.
    PipeServer *server_ptr = nullptr;
    PipeEndpoint::Handler echo = [&](VpnEasyServiceMessageType, ag::Uint8View data) {
        server_ptr->send(VPN_EASY_SVC_MSG_STATE_CHANGED, data);
    };
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), echo};
    server_ptr = &server;
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);

    const std::vector<uint8_t> payload = {0x10, 0x20, 0x30};
    auto frame = make_framed(VPN_EASY_SVC_MSG_START, payload);
    ASSERT_TRUE(write_all(client.get(), frame));

    ReceivedMessage rx{};
    ASSERT_TRUE(read_framed_message(client.get(), rx, TEST_TIMEOUT));
    EXPECT_EQ(rx.what, VPN_EASY_SVC_MSG_STATE_CHANGED);
    EXPECT_EQ(rx.payload, payload);

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerReconnectsAfterClientDisconnects) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    {
        Handle client = open_raw_client(m_pipe_name);
        ASSERT_TRUE(client);
        auto frame = make_framed(VPN_EASY_SVC_MSG_START, {});
        ASSERT_TRUE(write_all(client.get(), frame));
        ASSERT_TRUE(collector.wait_for_count(1, TEST_TIMEOUT));
        // Client closes here.
    }

    {
        Handle client = open_raw_client(m_pipe_name);
        ASSERT_TRUE(client);
        const std::vector<uint8_t> payload = {0x77};
        auto frame = make_framed(VPN_EASY_SVC_MSG_STOP, payload);
        ASSERT_TRUE(write_all(client.get(), frame));
        ASSERT_TRUE(collector.wait_for_count(2, TEST_TIMEOUT));
        auto msgs = collector.snapshot();
        EXPECT_EQ(msgs[0].what, VPN_EASY_SVC_MSG_START);
        EXPECT_EQ(msgs[0].payload.size(), 0);
        EXPECT_EQ(msgs[1].what, VPN_EASY_SVC_MSG_STOP);
        EXPECT_EQ(msgs[1].payload, payload);
    }

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ServerStopEventDuringActiveConnection_ExitsCleanly) {
    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);
    auto frame = make_framed(VPN_EASY_SVC_MSG_START, {});
    ASSERT_TRUE(write_all(client.get(), frame));
    ASSERT_TRUE(collector.wait_for_count(1, TEST_TIMEOUT));

    signal_stop();
    auto loop_result = runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(loop_result);
    EXPECT_TRUE(*loop_result);
}

TEST_F(PipeTest, ServerWithAuthenticatedUsersDescriptor_AcceptsConnections) {
    auto sd = PipeServer::for_authenticated_users();
    ASSERT_TRUE(sd);

    MessageCollector collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler(), sd.get()};

    // The descriptor is documented as consumed synchronously; freeing it now must be safe.
    sd.reset();

    LoopRunner runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client = open_raw_client(m_pipe_name);
    ASSERT_TRUE(client);
    auto frame = make_framed(VPN_EASY_SVC_MSG_START, {});
    ASSERT_TRUE(write_all(client.get(), frame));
    ASSERT_TRUE(collector.wait_for_count(1, TEST_TIMEOUT));

    signal_stop();
    ASSERT_TRUE(runner.wait_for(JOIN_TIMEOUT));
}

// ---------------------------------------------------------------------------
// PipeClient tests
// ---------------------------------------------------------------------------

TEST_F(PipeTest, ClientLoopFailsImmediately_WhenServerNotPresent) {
    MessageCollector collector;
    PipeClient client{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler(),
            std::chrono::milliseconds(50)};
    LoopRunner runner{m_stop_event.get(), [&] { return client.loop(); }};
    auto loop_result = runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(loop_result);
    EXPECT_FALSE(*loop_result);
}

TEST_F(PipeTest, ClientServerExchangeMessages) {
    // Server echoes any incoming message back as VPN_EASY_SVC_MSG_STATE_CHANGED.
    PipeServer *server_ptr = nullptr;
    PipeEndpoint::Handler server_handler = [&](VpnEasyServiceMessageType, ag::Uint8View data) {
        server_ptr->send(VPN_EASY_SVC_MSG_STATE_CHANGED, data);
    };
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), server_handler};
    server_ptr = &server;
    LoopRunner server_runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client_stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    MessageCollector client_collector;
    PipeClient client{m_pipe_name.c_str(), client_stop.get(), client_collector.make_handler()};
    LoopRunner client_runner{client_stop.get(), [&] { return client.loop(); }};

    ASSERT_TRUE(client.wait_connected());
    const std::vector<uint8_t> payload = {0xAB, 0xCD, 0xEF};
    client.send(VPN_EASY_SVC_MSG_START, {payload.data(), payload.size()});

    ASSERT_TRUE(client_collector.wait_for_count(1, TEST_TIMEOUT));
    auto msgs = client_collector.snapshot();
    ASSERT_EQ(msgs.size(), 1u);
    EXPECT_EQ(msgs[0].what, VPN_EASY_SVC_MSG_STATE_CHANGED);
    EXPECT_EQ(msgs[0].payload, payload);

    SetEvent(client_stop.get());
    auto client_result = client_runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(client_result);
    EXPECT_TRUE(*client_result);

    signal_stop();
    ASSERT_TRUE(server_runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ClientLoopExits_OnPeerDisconnect) {
    // Build a raw single-instance overlapped server pipe by hand.
    Handle server_pipe{CreateNamedPipeW(m_pipe_name.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 64 * 1024, 64 * 1024, 0, nullptr)};
    ASSERT_TRUE(server_pipe);

    MessageCollector collector;
    PipeClient client{m_pipe_name.c_str(), m_stop_event.get(), collector.make_handler()};
    LoopRunner runner{m_stop_event.get(), [&] { return client.loop(); }};

    // Accept the client's connection via overlapped ConnectNamedPipe.
    OVERLAPPED ol{};
    Handle ev{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    ol.hEvent = ev.get();
    BOOL ok = ConnectNamedPipe(server_pipe.get(), &ol);
    DWORD err = GetLastError();
    if (!ok && err == ERROR_IO_PENDING) {
        ASSERT_EQ(WaitForSingleObject(ol.hEvent,
                          static_cast<DWORD>(
                                  std::chrono::duration_cast<std::chrono::milliseconds>(TEST_TIMEOUT)
                                          .count())),
                WAIT_OBJECT_0);
        DWORD t = 0;
        ASSERT_TRUE(GetOverlappedResult(server_pipe.get(), &ol, &t, FALSE));
    } else if (!ok) {
        ASSERT_EQ(err, static_cast<DWORD>(ERROR_PIPE_CONNECTED));
    }

    // Tear down the server side; the client's loop() must exit gracefully (returning true).
    DisconnectNamedPipe(server_pipe.get());
    server_pipe.reset();

    auto loop_result = runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(loop_result);
    EXPECT_TRUE(*loop_result);
}

TEST_F(PipeTest, ClientStopEventCausesGracefulExit) {
    MessageCollector server_collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), server_collector.make_handler()};
    LoopRunner server_runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client_stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    MessageCollector client_collector;
    PipeClient client{m_pipe_name.c_str(), client_stop.get(), client_collector.make_handler()};
    LoopRunner client_runner{client_stop.get(), [&] { return client.loop(); }};

    std::this_thread::sleep_for(100ms);
    SetEvent(client_stop.get());
    auto client_result = client_runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(client_result);
    EXPECT_TRUE(*client_result);

    signal_stop();
    ASSERT_TRUE(server_runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ClientCanReconnect_ViaFreshInstance) {
    // The documented pattern: after the client's loop() exits, the caller may construct a new
    // PipeClient to reconnect. Verify two successive client instances both connect successfully.
    MessageCollector server_collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), server_collector.make_handler()};
    LoopRunner server_runner{m_stop_event.get(), [&] { return server.loop(); }};

    auto run_one_client = [&] {
        Handle stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        MessageCollector collector;
        PipeClient client{m_pipe_name.c_str(), stop.get(), collector.make_handler()};
        LoopRunner runner{stop.get(), [&] { return client.loop(); }};
        ASSERT_TRUE(client.wait_connected());
        const std::vector<uint8_t> payload = {0x01};
        client.send(VPN_EASY_SVC_MSG_START, {payload.data(), payload.size()});
        server_collector.wait_for_count(server_collector.count() + 1, TEST_TIMEOUT);
        SetEvent(stop.get());
        auto loop_result = runner.wait_for(JOIN_TIMEOUT);
        ASSERT_TRUE(loop_result);
        EXPECT_TRUE(*loop_result);
    };

    run_one_client();
    run_one_client();
    EXPECT_GE(server_collector.count(), 2u);

    signal_stop();
    auto loop_result = server_runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(loop_result);
    EXPECT_TRUE(*loop_result);
}

TEST_F(PipeTest, ClientStartConnect_RetriesUntilServerInstanceBecomesAvailable) {
    // Regression: PipeClient::start_connect must tolerate the brief race window during which the
    // single-instance server is mid-reconnect (CreateFileW returns ERROR_PIPE_BUSY or
    // ERROR_FILE_NOT_FOUND). Construct the client BEFORE the server exists; the connect must
    // succeed once the server appears within the retry deadline.
    Handle client_stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    MessageCollector client_collector;
    PipeClient client{m_pipe_name.c_str(), client_stop.get(), client_collector.make_handler(),
            std::chrono::seconds(2)};
    LoopRunner client_runner{client_stop.get(), [&] { return client.loop(); }};

    // Bring the server up after a short delay -- well within the client's retry budget.
    std::this_thread::sleep_for(200ms);
    MessageCollector server_collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), server_collector.make_handler()};
    LoopRunner server_runner{m_stop_event.get(), [&] { return server.loop(); }};

    // Once connected, the client should be able to send and the server should observe it.
    ASSERT_TRUE(client.wait_connected());
    const std::vector<uint8_t> payload = {0x99};
    client.send(VPN_EASY_SVC_MSG_START, {payload.data(), payload.size()});
    ASSERT_TRUE(server_collector.wait_for_count(1, TEST_TIMEOUT));

    SetEvent(client_stop.get());
    auto client_result = client_runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(client_result);
    EXPECT_TRUE(*client_result);

    signal_stop();
    auto server_result = server_runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(server_result);
    ASSERT_TRUE(*server_result);
}

TEST_F(PipeTest, ClientStartConnect_HonorsStopEventDuringRetry) {
    // No server exists; the client should keep retrying until the stop event is signaled, and
    // then return promptly (well under the configured connect timeout).
    Handle client_stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    MessageCollector client_collector;
    PipeClient client{m_pipe_name.c_str(), client_stop.get(), client_collector.make_handler(),
            std::chrono::seconds(5)};
    LoopRunner client_runner{client_stop.get(), [&] { return client.loop(); }};

    std::this_thread::sleep_for(150ms); // Let the client observe at least one retry slice.
    SetEvent(client_stop.get());
    auto client_result = client_runner.wait_for(std::chrono::seconds(2));
    ASSERT_TRUE(client_result);
    // start_connect() returning false on stop-event during retry is the contract: the loop never
    // truly began, so reporting a fatal start failure is the only available signal.
    EXPECT_FALSE(*client_result);
}

TEST_F(PipeTest, ClientWaitConnected_ReturnsTrue_AfterSuccessfulConnect) {
    MessageCollector server_collector;
    PipeServer server{m_pipe_name.c_str(), m_stop_event.get(), server_collector.make_handler()};
    LoopRunner server_runner{m_stop_event.get(), [&] { return server.loop(); }};

    Handle client_stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    MessageCollector client_collector;
    PipeClient client{m_pipe_name.c_str(), client_stop.get(), client_collector.make_handler()};
    LoopRunner client_runner{client_stop.get(), [&] { return client.loop(); }};

    EXPECT_TRUE(client.wait_connected());

    SetEvent(client_stop.get());
    ASSERT_TRUE(client_runner.wait_for(JOIN_TIMEOUT));
    signal_stop();
    ASSERT_TRUE(server_runner.wait_for(JOIN_TIMEOUT));
}

TEST_F(PipeTest, ClientWaitConnected_ReturnsFalse_OnConnectFailure) {
    // No server: the client's loop() will fail to connect within the (short) connect timeout.
    // wait_connected() must wake on that failure and return false rather than wait the full
    // user-supplied connect timeout.
    Handle client_stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    MessageCollector client_collector;
    PipeClient client{m_pipe_name.c_str(), client_stop.get(), client_collector.make_handler(),
            std::chrono::milliseconds(100)};
    LoopRunner client_runner{client_stop.get(), [&] { return client.loop(); }};

    auto t0 = std::chrono::steady_clock::now();
    EXPECT_FALSE(client.wait_connected());
    auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LT(elapsed, std::chrono::seconds(2)) << "wait_connected did not wake on connect failure";

    auto client_result = client_runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(client_result);
    EXPECT_FALSE(*client_result);
}

TEST_F(PipeTest, ClientWaitConnected_ReturnsFalse_OnTimeout) {
    // No server, no loop running: wait_connected() must respect its own timeout and return false.
    Handle client_stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    MessageCollector client_collector;
    PipeClient client{m_pipe_name.c_str(), client_stop.get(), client_collector.make_handler()};

    auto t0 = std::chrono::steady_clock::now();
    EXPECT_FALSE(client.wait_connected());
    auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_GE(elapsed, 100ms);
    EXPECT_LT(elapsed, std::chrono::seconds(1));
}

TEST_F(PipeTest, ClientWaitConnected_ReturnsFalse_OnStopEvent) {
    // No server, loop running: signal stop while wait_connected is blocked. It must return
    // false promptly (well under the connect timeout).
    Handle client_stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    MessageCollector client_collector;
    PipeClient client{m_pipe_name.c_str(), client_stop.get(), client_collector.make_handler(),
            std::chrono::seconds(5)};
    LoopRunner client_runner{client_stop.get(), [&] { return client.loop(); }};

    std::thread signaler([&] {
        std::this_thread::sleep_for(100ms);
        SetEvent(client_stop.get());
    });

    auto t0 = std::chrono::steady_clock::now();
    EXPECT_FALSE(client.wait_connected());
    auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LT(elapsed, std::chrono::seconds(2));

    signaler.join();
    auto client_result = client_runner.wait_for(JOIN_TIMEOUT);
    ASSERT_TRUE(client_result);
}

TEST_F(PipeTest, ClientConnectTimeout_ZeroSelectsDefault) {
    // A connect_timeout of 0 must select PipeClient::DEFAULT_CONNECT_TIMEOUT (500 ms). With no
    // server, loop() should fail at roughly that wallclock duration.
    Handle client_stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    MessageCollector client_collector;
    PipeClient client{m_pipe_name.c_str(), client_stop.get(), client_collector.make_handler(),
            std::chrono::milliseconds(0)};
    LoopRunner client_runner{client_stop.get(), [&] { return client.loop(); }};

    auto t0 = std::chrono::steady_clock::now();
    auto client_result = client_runner.wait_for(std::chrono::seconds(3));
    auto elapsed = std::chrono::steady_clock::now() - t0;
    ASSERT_TRUE(client_result);
    EXPECT_FALSE(*client_result);
    EXPECT_GE(elapsed, std::chrono::milliseconds(400));
    EXPECT_LT(elapsed, std::chrono::seconds(2));
}

// ---------------------------------------------------------------------------
// SecurityDescriptorPtr / for_authenticated_users
// ---------------------------------------------------------------------------

TEST(PipeSecurityDescriptor, ForAuthenticatedUsersReturnsValidDescriptor) {
    auto sd = PipeServer::for_authenticated_users();
    ASSERT_TRUE(sd);
    ASSERT_NE(sd.get(), nullptr);
    EXPECT_TRUE(IsValidSecurityDescriptor(sd.get()));
}
