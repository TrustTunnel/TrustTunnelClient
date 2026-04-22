#pragma once

#include <atomic>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "common/defs.h"
#include "vpn/vpn_easy_service.h"

namespace ag::vpn_easy {

/**
 * Asynchronous named-pipe server for the VPN easy-service control protocol.
 *
 * The server owns a single byte-stream named pipe instance. After construction the caller drives the IO
 * loop by calling `loop()` on a worker thread; the loop returns once the externally-provided `stop_event`
 * becomes signaled (or on a fatal error). The server waits for a client to connect, then concurrently
 * reads framed messages (see `VpnEasyServiceMessageType`) from the client (delivered via the user
 * callback) and writes framed messages enqueued via `send()`. When the client disconnects, the server
 * transparently reconnects and waits for a new client.
 *
 * `send()` is thread-safe and may be called from any thread, including from inside the receive callback.
 * If no client is currently connected the message is dropped. If the queue overflows, the oldest pending
 * messages are dropped.
 */
class PipeServer {
public:
    /**
     * Callback invoked from `loop()`'s thread for every fully-received message.
     * The `data` view is valid only for the duration of the call.
     */
    using Handler = std::function<void(VpnEasyServiceMessageType what, ag::Uint8View data)>;

    /**
     * @param pipe_name Full named-pipe name (e.g. `\\.\pipe\my_pipe`).
     * @param stop_event Externally-owned manual-reset event. When signaled, `loop()` returns `true`.
     *                   Ownership is NOT transferred.
     * @param handler Message receive callback. Must be non-null.
     */
    PipeServer(const wchar_t *pipe_name, HANDLE stop_event, Handler handler);

    ~PipeServer();

    PipeServer(const PipeServer &) = delete;
    PipeServer &operator=(const PipeServer &) = delete;
    PipeServer(PipeServer &&) = delete;
    PipeServer &operator=(PipeServer &&) = delete;

    /**
     * Run the asynchronous IO loop until `stop_event` is signaled or a fatal error occurs.
     * @return `true` if stopped via the stop event, `false` on fatal error.
     */
    bool loop();

    /**
     * Enqueue a message to be sent to the currently-connected client. Thread-safe.
     * Drops the message if no client is connected. If the internal queue is full,
     * the oldest pending messages are dropped.
     */
    void send(VpnEasyServiceMessageType what, ag::Uint8View data);

private:
    static constexpr size_t MAX_PENDING_WRITES = 100;
    // Maximum payload size of a single message. Messages larger than this are rejected and the
    // connection is dropped (protocol violation / DoS protection).
    static constexpr size_t MAX_MESSAGE_SIZE = 16 * 1024;
    // Receive buffer size: large enough to hold one full message plus its 8-byte header.
    static constexpr size_t INPUT_BUF_SIZE = MAX_MESSAGE_SIZE + 2 * sizeof(uint32_t);
    static constexpr DWORD PIPE_BUFFER_SIZE = 64 * 1024;

    struct PendingWrite {
        std::vector<uint8_t> data;
        size_t written;
    };

    HANDLE m_pipe = INVALID_HANDLE_VALUE;
    HANDLE m_stop_event = nullptr;
    HANDLE m_io_event = nullptr;   // Signaled on ConnectNamedPipe/ReadFile completion.
    HANDLE m_write_event = nullptr; // Signaled on WriteFile completion.
    HANDLE m_wake_event = nullptr;  // Set by send() to wake the loop.

    OVERLAPPED m_olr{}; // For ConnectNamedPipe and ReadFile.
    OVERLAPPED m_olw{}; // For WriteFile.

    Handler m_handler;

    // Connection state. Written by the loop thread; read by send() (any thread).
    std::atomic<bool> m_connected{false};
    bool m_read_pending = false;
    bool m_write_pending = false;

    std::vector<uint8_t> m_input_buf;
    size_t m_input_buf_used = 0;

    std::mutex m_pending_writes_lock;
    std::list<PendingWrite> m_pending_writes; // Guarded by m_pending_writes_lock.

    // Owned exclusively by the loop thread: the message currently being written (possibly with an
    // overlapped WriteFile in flight). Moved here from m_pending_writes under the lock and kept
    // alive until the write fully completes, so that send() can never free the in-flight buffer.
    std::optional<PendingWrite> m_inflight_write;

    static HANDLE create_pipe(const wchar_t *pipe_name);
    static std::vector<uint8_t> compose_message(VpnEasyServiceMessageType what, ag::Uint8View data);

    bool start_connect();
    bool finalize_connect();
    bool start_read();
    bool complete_read();
    bool handle_input();
    bool pump_writes();
    bool complete_write();
    void disconnect_and_reset();
};

} // namespace ag::vpn_easy

