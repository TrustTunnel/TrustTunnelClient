#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "common/defs.h"
#include "common/logger.h"
#include "vpn/vpn_easy_service.h"

namespace ag::vpn_easy {

namespace detail {
/** Free a security descriptor returned by an SDDL helper. Used as the deleter for `SecurityDescriptorPtr`. */
void free_security_descriptor(SECURITY_DESCRIPTOR *sd);
} // namespace detail

/** Owning pointer for a security descriptor allocated via `LocalAlloc` (e.g. by SDDL helpers). */
using SecurityDescriptorPtr = ag::UniquePtr<SECURITY_DESCRIPTOR, &detail::free_security_descriptor>;

/**
 * Asynchronous named-pipe endpoint base class for the VPN easy-service control protocol.
 *
 * Holds all framing, queueing, overlapped-IO and event-loop machinery shared by both ends of the
 * pipe. Subclasses implement only:
 *   - how a pipe handle is acquired (`start_connect()`),
 *   - how a posted overlapped connect completion is reaped (`finalize_connect()`),
 *   - how the pipe handle is torn down on disconnect (`teardown_pipe()`),
 *   - and the disconnect policy (`should_reconnect_on_disconnect()`).
 *
 * After construction, the caller drives the IO loop by calling `loop()` on a worker thread; the
 * loop returns once the externally-provided `stop_event` becomes signaled, the peer disconnects
 * (only for endpoints whose `should_reconnect_on_disconnect()` returns `false`), or a fatal
 * error occurs.
 *
 * `send()` is thread-safe and may be called from any thread, including from inside the receive
 * callback. If the endpoint is not currently connected the message is dropped. If the queue
 * overflows, the oldest pending messages are dropped.
 */
class PipeEndpoint {
public:
    /**
     * Callback invoked from `loop()`'s thread for every fully-received message.
     * The `data` view is valid only for the duration of the call.
     */
    using Handler = std::function<void(VpnEasyServiceMessageType what, ag::Uint8View data)>;

    virtual ~PipeEndpoint();

    PipeEndpoint(const PipeEndpoint &) = delete;
    PipeEndpoint &operator=(const PipeEndpoint &) = delete;
    PipeEndpoint(PipeEndpoint &&) = delete;
    PipeEndpoint &operator=(PipeEndpoint &&) = delete;

    /**
     * Run the asynchronous IO loop until `stop_event` is signaled, the peer disconnects (for
     * non-reconnecting endpoints), or a fatal error occurs.
     * @return `true` if stopped via the stop event or a graceful peer disconnect, `false` on
     *         fatal error.
     */
    bool loop();

    /**
     * Enqueue a message to be sent to the currently-connected peer. Thread-safe.
     * Drop the message if no peer is connected. If the internal queue is full, drop the oldest
     * pending messages.
     */
    void send(VpnEasyServiceMessageType what, ag::Uint8View data);

protected:
    /**
     * @param stop_event Externally-owned manual-reset event. When signaled, `loop()` returns `true`.
     *                   Ownership is NOT transferred.
     * @param handler    Message receive callback. Must be non-null.
     * @param logger     Logger to use for diagnostic messages.
     */
    PipeEndpoint(HANDLE stop_event, Handler handler, ag::Logger &logger);

    /**
     * Subclass hook: acquire/initiate the pipe connection. On success, either:
     *   - mark `m_connected` true synchronously and `SetEvent(m_wake_event)`, or
     *   - leave `m_connected` false and post an overlapped op on `m_olr`/`m_io_event`; the loop
     *     will then call `finalize_connect()` when `m_io_event` fires.
     * Implementations MUST call `prepare_for_connect()` first to clear per-connection state.
     * @return `true` on success (sync or pending), `false` on fatal error (`loop()` returns false).
     */
    virtual bool start_connect() = 0;

    /**
     * Subclass hook: reap the completion of an overlapped connect posted by `start_connect()`,
     * called when `m_io_event` fires while not yet connected. Default returns `false` (no
     * overlapped connect was posted; an `m_io_event` wake here is unexpected).
     */
    virtual bool finalize_connect() {
        return false;
    }

    /**
     * Subclass hook: tear down the pipe handle after pending IO has been cancelled and drained.
     * Called from `disconnect_and_reset()`. Implementations typically call `DisconnectNamedPipe`
     * (server -- handle is reused) or `CloseHandle` and reset `m_pipe` to `INVALID_HANDLE_VALUE`
     * (client -- handle is single-use).
     */
    virtual void teardown_pipe() = 0;

    /**
     * Subclass hook: report the disconnect policy. Returning `true` (the default) causes the
     * loop to invoke `start_connect()` again after each disconnect; returning `false` causes
     * `loop()` to return `true` after the first disconnect. `PipeClient` overrides to return
     * `false`.
     */
    virtual bool should_reconnect_on_disconnect() const {
        return true;
    }

    /**
     * Reset per-connection state and event handles to their initial values. Subclasses MUST call
     * this at the top of `start_connect()`.
     */
    void prepare_for_connect();

    /**
     * Cancel any pending overlapped IO on `m_pipe` and synchronously wait for the cancellations
     * to land. Used by subclass destructors to safely tear down a still-active endpoint.
     * Caller must ensure `m_pipe != INVALID_HANDLE_VALUE`.
     */
    void cancel_pending_io();

    // Pipe handle. Owned by the subclass: the server creates it once in its constructor and
    // re-uses it across `DisconnectNamedPipe`; the client creates it in `start_connect()` and
    // destroys it in `teardown_pipe()`.
    HANDLE m_pipe = INVALID_HANDLE_VALUE;

    // Overlapped state, used by both subclass connect logic (`m_olr`) and the shared read/write
    // pipeline. Subclasses must not touch these except as documented above.
    OVERLAPPED m_olr{};             ///< For overlapped connect (subclass) / `ReadFile` (base).
    OVERLAPPED m_olw{};             ///< For `WriteFile` (base only).
    HANDLE m_io_event = nullptr;    ///< Signaled on overlapped connect or read completion.
    HANDLE m_write_event = nullptr; ///< Signaled on write completion.
    HANDLE m_wake_event = nullptr;  ///< Set by `send()` (and by sync-connect paths) to wake the loop.

    // Connection state. Written by the loop thread; read by `send()` (any thread).
    std::atomic<bool> m_connected{false};

    // Logger. Bound to a static ag::Logger owned by the subclass's translation unit.
    ag::Logger &m_logger;

    // Externally-owned stop event. Exposed to subclasses so that long-running connect retries
    // (e.g. PipeClient::start_connect) can be interrupted promptly when the loop is asked to stop.
    HANDLE stop_event() const {
        return m_stop_event;
    }

private:
    static constexpr size_t MAX_PENDING_WRITES = 100;
    // Maximum payload size of a single message. Messages larger than this are rejected and the
    // connection is dropped (protocol violation / DoS protection).
    static constexpr size_t MAX_MESSAGE_SIZE = 16 * 1024;
    // Receive buffer size: large enough to hold one full message plus its 8-byte header.
    static constexpr size_t INPUT_BUF_SIZE = MAX_MESSAGE_SIZE + 2 * sizeof(uint32_t);

    struct PendingWrite {
        std::vector<uint8_t> data;
        size_t written;
    };

    HANDLE m_stop_event = nullptr;
    Handler m_handler;
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

    static std::vector<uint8_t> compose_message(VpnEasyServiceMessageType what, ag::Uint8View data);

    // Returns nullopt to continue the loop; otherwise the value `loop()` should return.
    std::optional<bool> handle_disconnect();

    bool start_read();
    bool complete_read();
    bool handle_input();
    bool pump_writes();
    bool complete_write();
    void disconnect_and_reset();
};

/**
 * Server endpoint: owns a single byte-stream named pipe instance, accepts one client at a time,
 * and transparently reconnects (waits for a new client) when the current client disconnects.
 */
class PipeServer : public PipeEndpoint {
public:
    /**
     * Create a security descriptor that grants GENERIC_READ | GENERIC_WRITE to
     * NT AUTHORITY\Authenticated Users, and full control to SYSTEM and BUILTIN\Administrators.
     * Suitable for a service-side IPC named pipe that must be reachable from any locally
     * authenticated user session. Returns null on failure.
     */
    static SecurityDescriptorPtr for_authenticated_users();

    /**
     * @param pipe_name           Full named-pipe name (e.g. `\\.\pipe\my_pipe`).
     * @param stop_event          See `PipeEndpoint`.
     * @param handler             See `PipeEndpoint`.
     * @param security_descriptor Optional security descriptor for the pipe. If null (the default),
     *                            the system default DACL is used. The pointer is consumed
     *                            synchronously by the constructor; the caller may destroy the
     *                            descriptor immediately after construction returns.
     */
    PipeServer(const wchar_t *pipe_name, HANDLE stop_event, Handler handler,
            SECURITY_DESCRIPTOR *security_descriptor = nullptr);
    ~PipeServer() override;

protected:
    bool start_connect() override;
    bool finalize_connect() override;
    void teardown_pipe() override;
    // Default `Reconnect` policy is exactly what the server wants.

private:
    static constexpr DWORD PIPE_BUFFER_SIZE = 64 * 1024;

    static HANDLE create_pipe(const wchar_t *pipe_name, SECURITY_DESCRIPTOR *security_descriptor);
};

/**
 * Client endpoint: opens a connection to an existing named-pipe server. The IO loop exits on
 * peer disconnect (returning `true` from `loop()`); the caller should construct a new `PipeClient` to reconnect.
 */
class PipeClient : public PipeEndpoint {
public:
    /** Default total timeout used by `start_connect()` when the constructor is passed `0`. */
    static constexpr std::chrono::milliseconds DEFAULT_CONNECT_TIMEOUT{500};

    /**
     * @param pipe_name       Full named-pipe name (e.g. `\\.\pipe\my_pipe`).
     * @param stop_event      See `PipeEndpoint`.
     * @param handler         See `PipeEndpoint`.
     * @param connect_timeout Maximum total time `start_connect()` will spend retrying
     *                        `CreateFileW` while the server is briefly unavailable
     *                        (e.g. mid-reconnect of a previous client). A value of `0` selects
     *                        `DEFAULT_CONNECT_TIMEOUT`. Negative values are treated as `0`.
     */
    PipeClient(const wchar_t *pipe_name, HANDLE stop_event, Handler handler,
            std::chrono::milliseconds connect_timeout = std::chrono::milliseconds{0});
    ~PipeClient() override;

    /**
     * Block until the client has successfully connected to the server (i.e. `start_connect()`,
     * driven by `loop()` on another thread, has succeeded), or the externally-supplied stop event
     * is signaled -- whichever happens first. Thread-safe; may be called
     * from any thread, including before `loop()` has started.
     * @return `true` if the connection is established within the timeout, `false` otherwise
     *         (timeout, stop event signaled, or fatal connect failure).
     */
    bool wait_connected();

protected:
    bool start_connect() override;
    void teardown_pipe() override;
    bool should_reconnect_on_disconnect() const override {
        return false;
    }

private:
    std::wstring m_pipe_name;
    std::chrono::milliseconds m_connect_timeout;
    // Manual-reset event signaled by start_connect() on success and by loop() on fatal start
    // failure. Used by wait_connected() so callers can synchronize without polling. Reset at the
    // top of every start_connect() attempt so that a fresh PipeClient instance starts clean.
    HANDLE m_connected_or_failed_event = nullptr;
};

} // namespace ag::vpn_easy
