#include "pipe.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <utility>

#include "common/logger.h"
#include "common/system_error.h"
#include "vpn/internal/wire_utils.h"

namespace ag::vpn_easy {

static ag::Logger g_logger{"PipeServer"};

PipeServer::PipeServer(const wchar_t *pipe_name, HANDLE stop_event, Handler handler)
        : m_pipe{create_pipe(pipe_name)}
        , m_stop_event{stop_event}
        , m_io_event{CreateEventW(nullptr, TRUE, FALSE, nullptr)}
        , m_write_event{CreateEventW(nullptr, TRUE, FALSE, nullptr)}
        , m_wake_event{CreateEventW(nullptr, FALSE, FALSE, nullptr)}
        , m_handler{std::move(handler)} {
    assert(m_handler);
    m_olr.hEvent = m_io_event;
    m_olw.hEvent = m_write_event;
    m_input_buf.resize(INPUT_BUF_SIZE);
}

PipeServer::~PipeServer() {
    if (m_pipe != INVALID_HANDLE_VALUE) {
        CancelIoEx(m_pipe, nullptr);
        if (m_write_pending) {
            DWORD ignored = 0;
            GetOverlappedResult(m_pipe, &m_olw, &ignored, TRUE);
        }
        if (m_read_pending || !m_connected.load(std::memory_order_relaxed)) {
            DWORD ignored = 0;
            GetOverlappedResult(m_pipe, &m_olr, &ignored, TRUE);
        }
        DisconnectNamedPipe(m_pipe);
        CloseHandle(m_pipe);
    }
    if (m_io_event != nullptr) {
        CloseHandle(m_io_event);
    }
    if (m_write_event != nullptr) {
        CloseHandle(m_write_event);
    }
    if (m_wake_event != nullptr) {
        CloseHandle(m_wake_event);
    }
}

HANDLE PipeServer::create_pipe(const wchar_t *pipe_name) {
    HANDLE h = CreateNamedPipeW(pipe_name,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, // single instance
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        errlog(g_logger, "CreateNamedPipeW: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
    }
    return h;
}

std::vector<uint8_t> PipeServer::compose_message(VpnEasyServiceMessageType what, ag::Uint8View data) {
    assert(data.size() < size_t(UINT32_MAX));
    std::vector<uint8_t> ret;
    ret.resize(sizeof(uint32_t) + sizeof(uint32_t) + data.size());
    ag::wire_utils::Writer w{{ret.data(), ret.size()}};
    w.put_u32(static_cast<uint32_t>(what));
    w.put_u32(static_cast<uint32_t>(data.size()));
    w.put_data(data);
    return ret;
}

void PipeServer::send(VpnEasyServiceMessageType what, ag::Uint8View data) {
    {
        std::scoped_lock l{m_pending_writes_lock};
        // disconnect_and_reset() stores `false` BEFORE taking this lock, so any push that
        // happens-before disconnect's lock acquisition will be observed (and cleared) by
        // disconnect, and any push that happens-after will see `false` here and bail out.
        if (!m_connected.load(std::memory_order_relaxed)) {
            return;
        }
        if (m_pending_writes.size() == MAX_PENDING_WRITES) {
            static_assert(MAX_PENDING_WRITES > 0);
            m_pending_writes.pop_front();
        }
        m_pending_writes.push_back(PendingWrite{compose_message(what, data), 0});
    }
    SetEvent(m_wake_event);
}

bool PipeServer::loop() {
    if (m_pipe == INVALID_HANDLE_VALUE || m_io_event == nullptr || m_write_event == nullptr
            || m_wake_event == nullptr) {
        return false;
    }

    if (!start_connect()) {
        return false;
    }

    HANDLE events[] = {m_stop_event, m_wake_event, m_io_event, m_write_event};
    constexpr DWORD EVENT_COUNT = static_cast<DWORD>(std::size(events));
    for (;;) {
        DWORD wait = WaitForMultipleObjects(EVENT_COUNT, events, FALSE, INFINITE);
        if (wait >= WAIT_OBJECT_0 + EVENT_COUNT) {
            errlog(g_logger, "WaitForMultipleObjects: {:#x}, GetLastError: {} ({})", wait, GetLastError(),
                    ag::sys::strerror(GetLastError()));
            return false;
        }

        DWORD idx = wait - WAIT_OBJECT_0;
        if (idx == 0) {
            // Stop event.
            return true;
        }

        if (idx == 2) {
            // m_io_event: ConnectNamedPipe or ReadFile completed.
            if (!m_connected.load(std::memory_order_relaxed)) {
                if (!finalize_connect()) {
                    // Connection failed; restart the connect.
                    disconnect_and_reset();
                    if (!start_connect()) {
                        return false;
                    }
                    continue;
                }
            } else if (m_read_pending) {
                if (!complete_read()) {
                    disconnect_and_reset();
                    if (!start_connect()) {
                        return false;
                    }
                    continue;
                }
            }
        }

        if (idx == 3 && m_write_pending) {
            // m_write_event: WriteFile completed.
            if (!complete_write()) {
                disconnect_and_reset();
                if (!start_connect()) {
                    return false;
                }
                continue;
            }
        }

        // After any wake-up, try to issue a fresh read (if connected and not already pending) and
        // pump as many writes as possible.
        if (m_connected.load(std::memory_order_relaxed) && !m_read_pending) {
            if (!start_read()) {
                disconnect_and_reset();
                if (!start_connect()) {
                    return false;
                }
                continue;
            }
        }

        if (m_connected.load(std::memory_order_relaxed) && !pump_writes()) {
            disconnect_and_reset();
            if (!start_connect()) {
                return false;
            }
            continue;
        }
    }
}

bool PipeServer::start_connect() {
    m_connected.store(false, std::memory_order_relaxed);
    m_read_pending = false;
    m_write_pending = false;
    m_input_buf_used = 0;
    ResetEvent(m_io_event);
    ResetEvent(m_write_event);

    if (ConnectNamedPipe(m_pipe, &m_olr)) {
        // Synchronous success (very rare for overlapped pipes). The OVERLAPPED was not really
        // used by the kernel in this case, so do not call finalize_connect (which would call
        // GetOverlappedResult on it). Mark connected directly and kick the loop.
        ResetEvent(m_io_event); // Defensive: kernel may have signaled on sync completion.
        m_connected.store(true, std::memory_order_relaxed);
        SetEvent(m_wake_event);
        infolog(g_logger, "client connected (sync)");
        return true;
    }
    DWORD err = GetLastError();
    if (err == ERROR_PIPE_CONNECTED) {
        // A client connected between CreateNamedPipe and ConnectNamedPipe. No overlapped op was
        // submitted; mark connected directly.
        m_connected.store(true, std::memory_order_relaxed);
        SetEvent(m_wake_event);
        infolog(g_logger, "client connected (already connected)");
        return true;
    }
    if (err == ERROR_IO_PENDING) {
        return true;
    }
    errlog(g_logger, "ConnectNamedPipe: {} ({})", err, ag::sys::strerror(err));
    return false;
}

bool PipeServer::finalize_connect() {
    DWORD transferred = 0;
    if (!GetOverlappedResult(m_pipe, &m_olr, &transferred, FALSE)) {
        // ERROR_IO_INCOMPLETE here would indicate a bug: the kernel signals m_io_event only on
        // completion, so a wake on it should always coincide with a completed op. Treat any
        // failure as fatal for this connection -- the caller will disconnect and reconnect.
        // (Trying to ResetEvent in the IO_INCOMPLETE case would race with the kernel setting it
        // on real completion and could lose the signal.)
        DWORD err = GetLastError();
        warnlog(g_logger, "GetOverlappedResult(connect): {} ({})", err, ag::sys::strerror(err));
        return false;
    }
    ResetEvent(m_io_event);
    m_connected.store(true, std::memory_order_relaxed);
    infolog(g_logger, "client connected");
    return true;
}

bool PipeServer::start_read() {
    if (m_input_buf_used >= m_input_buf.size()) {
        // Buffer is full but no complete message could be parsed -- impossible if MAX_MESSAGE_SIZE
        // is honored, so this indicates a protocol violation. Drop the connection.
        warnlog(g_logger, "input buffer full ({} bytes) with no parsable message; dropping connection",
                m_input_buf_used);
        return false;
    }
    DWORD read_size = 0;
    BOOL ok = ReadFile(m_pipe, m_input_buf.data() + m_input_buf_used,
            static_cast<DWORD>(m_input_buf.size() - m_input_buf_used), &read_size, &m_olr);
    if (ok) {
        // Synchronous completion. The kernel may have signaled m_io_event in this case (the
        // docs are inconsistent), so reset it here to avoid a spurious wake on the next WFMO.
        // For async (ERROR_IO_PENDING), the kernel resets the event itself when queueing the IO.
        ResetEvent(m_io_event);
        m_input_buf_used += read_size;
        return handle_input();
    }
    DWORD err = GetLastError();
    if (err == ERROR_IO_PENDING) {
        m_read_pending = true;
        return true;
    }
    if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED || err == ERROR_NO_DATA) {
        infolog(g_logger, "ReadFile: client disconnected ({}: {})", err, ag::sys::strerror(err));
        return false; // Triggers reconnect.
    }
    warnlog(g_logger, "ReadFile: {} ({})", err, ag::sys::strerror(err));
    return false;
}

bool PipeServer::complete_read() {
    DWORD read_size = 0;
    if (!GetOverlappedResult(m_pipe, &m_olr, &read_size, FALSE)) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED || err == ERROR_OPERATION_ABORTED) {
            infolog(g_logger, "GetOverlappedResult(read): client disconnected ({}: {})", err,
                    ag::sys::strerror(err));
            return false;
        }
        // ERROR_IO_INCOMPLETE falls through here too: see finalize_connect for rationale.
        warnlog(g_logger, "GetOverlappedResult(read): {} ({})", err, ag::sys::strerror(err));
        return false;
    }
    ResetEvent(m_io_event);
    m_read_pending = false;
    if (read_size == 0) {
        infolog(g_logger, "ReadFile: EOF, client disconnected");
        return false; // EOF -> reconnect.
    }
    m_input_buf_used += read_size;
    return handle_input();
}

bool PipeServer::handle_input() {
    for (;;) {
        ag::wire_utils::Reader r{{m_input_buf.data(), m_input_buf_used}};
        auto what = r.get_u32();
        auto size = r.get_u32();
        if (!what.has_value() || !size.has_value()) {
            return true; // Need more bytes for the header.
        }
        if (*size > MAX_MESSAGE_SIZE) {
            warnlog(g_logger, "incoming message size {} exceeds MAX_MESSAGE_SIZE ({}); dropping connection",
                    *size, MAX_MESSAGE_SIZE);
            return false;
        }
        auto data = r.get_bytes(*size);
        if (!data.has_value()) {
            return true; // Need more bytes for the payload.
        }
        m_handler(static_cast<VpnEasyServiceMessageType>(*what), *data);
        ag::Uint8View remaining = r.get_buffer();
        std::memmove(m_input_buf.data(), remaining.data(), remaining.size());
        m_input_buf_used = remaining.size();
    }
}

bool PipeServer::pump_writes() {
    while (!m_write_pending) {
        if (!m_inflight_write.has_value()) {
            // Try to dequeue the next message under the lock, then drop the lock so that
            // WriteFile (and any pending kernel reads from the buffer) operate on memory
            // that send() can no longer touch.
            std::scoped_lock l{m_pending_writes_lock};
            if (m_pending_writes.empty()) {
                return true;
            }
            m_inflight_write.emplace(std::move(m_pending_writes.front()));
            m_pending_writes.pop_front();
        }

        PendingWrite &w = *m_inflight_write;
        DWORD written = 0;
        BOOL ok = WriteFile(m_pipe, w.data.data() + w.written,
                static_cast<DWORD>(w.data.size() - w.written), &written, &m_olw);
        if (ok) {
            // Synchronous completion. The kernel may have signaled m_write_event (the docs are
            // inconsistent), so reset it here to avoid a spurious wake on the next WFMO.
            // For async (ERROR_IO_PENDING), the kernel resets the event itself when queueing.
            ResetEvent(m_write_event);
            w.written += written;
            if (w.written == w.data.size()) {
                m_inflight_write.reset();
            }
            continue;
        }
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            m_write_pending = true;
            return true;
        }
        if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED || err == ERROR_NO_DATA) {
            infolog(g_logger, "WriteFile: client disconnected ({}: {})", err, ag::sys::strerror(err));
            return false;
        }
        warnlog(g_logger, "WriteFile: {} ({})", err, ag::sys::strerror(err));
        return false;
    }
    return true;
}

bool PipeServer::complete_write() {
    DWORD written = 0;
    if (!GetOverlappedResult(m_pipe, &m_olw, &written, FALSE)) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED || err == ERROR_OPERATION_ABORTED) {
            infolog(g_logger, "GetOverlappedResult(write): client disconnected ({}: {})", err,
                    ag::sys::strerror(err));
            return false;
        }
        // ERROR_IO_INCOMPLETE falls through here too: see finalize_connect for rationale.
        warnlog(g_logger, "GetOverlappedResult(write): {} ({})", err, ag::sys::strerror(err));
        return false;
    }
    // Consume the kernel-set completion signal so WFMO doesn't keep firing on m_write_event.
    ResetEvent(m_write_event);
    m_write_pending = false;
    if (m_inflight_write.has_value()) {
        PendingWrite &w = *m_inflight_write;
        w.written += written;
        if (w.written == w.data.size()) {
            m_inflight_write.reset();
        }
    }
    return true;
}

void PipeServer::disconnect_and_reset() {
    // Mark disconnected BEFORE taking the lock, so that any send() that subsequently acquires the
    // lock observes `false` and bails out. Any send() already holding (or already past) the lock
    // happens-before our lock acquisition below, so its push will be cleared by the clear() call.
    m_connected.store(false, std::memory_order_relaxed);
    {
        std::scoped_lock l{m_pending_writes_lock};
        m_pending_writes.clear();
    }
    CancelIoEx(m_pipe, nullptr);
    if (m_read_pending) {
        DWORD ignored = 0;
        GetOverlappedResult(m_pipe, &m_olr, &ignored, TRUE);
    }
    if (m_write_pending) {
        DWORD ignored = 0;
        GetOverlappedResult(m_pipe, &m_olw, &ignored, TRUE);
    }
    // Safe to drop the in-flight buffer now: the kernel has acknowledged the cancel.
    m_inflight_write.reset();
    DisconnectNamedPipe(m_pipe);
    // Both event handles may have been left signaled by GetOverlappedResult(TRUE) above.
    ResetEvent(m_io_event);
    ResetEvent(m_write_event);
    m_read_pending = false;
    m_write_pending = false;
    m_input_buf_used = 0;
}

} // namespace ag::vpn_easy
