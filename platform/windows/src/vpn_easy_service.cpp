#include "vpn/vpn_easy_service.h"
#include "vpn/vpn_easy.h"

#include <cstdio>
#include <list>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "common/defs.h"
#include "common/logger.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "common/system_error.h"
#include "vpn/internal/wire_utils.h"

static ag::Logger g_logger{"VPN_EASY_SERVICE"};

static std::wstring g_pipe_name;
static SERVICE_STATUS_HANDLE g_status_handle;
static HANDLE g_shutdown_event;

class PipeServer {
public:
    using Handler = std::function<void(VpnEasyServiceMessageType what, ag::Uint8View data)>;

    /** Ownership of `stop_event` is not transferred. */
    PipeServer(const wchar_t *pipe_name, HANDLE stop_event, Handler handler)
            : m_pipe{create_pipe(pipe_name)}
            , m_stop_event{stop_event}
            , m_io_event{CreateEventW(nullptr, TRUE, FALSE, nullptr)}
            , m_handler{std::move(handler)} {
        m_olr.hEvent = m_io_event;
        m_olw.hEvent = m_io_event;
    }

    void send(VpnEasyServiceMessageType what, ag::Uint8View data) {
        {
            std::scoped_lock l{m_pending_writes_lock};
            if (m_pending_writes.size() == MAX_PENDING_WRITES) {
                static_assert(MAX_PENDING_WRITES > 0);
                m_pending_writes.pop_front();
            }
            m_pending_writes.emplace_back(compose_message(what, data));
        }
        SetEvent(m_io_event);
    }

    /**
     * Async IO loop. Block until the stop event is set. Return `true` if stopped because the stop event
     * was set. Return `false` if stopped because of an error.
     */
    bool loop() {
        if (!reconnect()) {
            return false;
        }

        HANDLE events[] = {m_stop_event, m_io_event};
        for (;;) {
            DWORD event_idx = WaitForMultipleObjects(2, &events[0], FALSE, INFINITE);
            if (event_idx < WAIT_OBJECT_0 || event_idx > WAIT_OBJECT_0 + 1) {
                errlog(g_logger, "WaitForMultipleObjects: {:#x}, GetLastError: {} ({})", event_idx, GetLastError(),
                        ag::sys::strerror(GetLastError()));
                return false;
            }
            event_idx -= WAIT_OBJECT_0;
            if (event_idx == 0) {
                return true;
            }

            if (!m_connected) {
                if (!GetOverlappedResult(m_pipe, &m_olr, nullptr, FALSE)) {
                    continue; // Still connecting.
                }
                m_connected = true;
            }

            if (!do_read()) {
                return false;
            }

            if (!do_write()) {
                return false;
            }
        }
    }

    ~PipeServer() {
        CancelIo(m_pipe);
        GetOverlappedResult(m_pipe, &m_olw, nullptr, TRUE);
        GetOverlappedResult(m_pipe, &m_olr, nullptr, TRUE);
        CloseHandle(m_pipe);
        CloseHandle(m_io_event);
    }

    PipeServer(const PipeServer &) = delete;
    PipeServer &operator=(const PipeServer &) = delete;

    PipeServer(PipeServer &&) = delete;
    PipeServer &operator=(PipeServer &&) = delete;

private:
    static constexpr size_t MAX_PENDING_WRITES = 100;
    static constexpr size_t INPUT_BUF_INITIAL_SIZE = 16 * 1024;

    HANDLE m_pipe;
    HANDLE m_stop_event;
    HANDLE m_io_event;
    Handler m_handler;
    bool m_connected : 1 = false;
    bool m_read_pending : 1 = false;
    bool m_write_pending : 1 = false;
    OVERLAPPED m_olr{};
    OVERLAPPED m_olw{};

    struct Write {
        std::vector<uint8_t> data;
        size_t written;
    };

    std::mutex m_pending_writes_lock;
    std::list<Write> m_pending_writes;

    std::vector<uint8_t> m_input_buf;
    size_t m_input_buf_used;

    static Write compose_message(VpnEasyServiceMessageType what, ag::Uint8View data) {
        assert(data.size() < size_t(UINT32_MAX));
        std::vector<uint8_t> ret;
        ret.resize(sizeof(uint32_t) + sizeof(uint32_t) + data.size());
        ag::wire_utils::Writer w{{ret.data(), ret.size()}};
        w.put_u32(what);
        w.put_u32(data.size());
        w.put_data(data);
        return {std::move(ret), 0};
    }

    static HANDLE create_pipe(const wchar_t *pipe_name);

    bool do_read() {
        DWORD read_size = 0;
        if (m_read_pending) {
            if (!GetOverlappedResult(m_pipe, &m_olr, &read_size, FALSE)) {
                return true;
            }
            m_read_pending = false;
            m_input_buf_used += read_size;
            handle_input();
        }
        for (;;) {
            m_input_buf.resize(std::max(INPUT_BUF_INITIAL_SIZE, m_input_buf_used * 2));
            if (!ReadFile(m_pipe, m_input_buf.data() + m_input_buf_used, m_input_buf.size() - m_input_buf_used,
                        &read_size, &m_olr)) {
                if (ERROR_IO_PENDING == GetLastError()) {
                    m_read_pending = true;
                    return true;
                }
                if (ERROR_PIPE_NOT_CONNECTED == GetLastError()) {
                    return reconnect();
                }
                errlog(g_logger, "ReadFile: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
                return false;
            }
            m_input_buf_used += read_size;
            handle_input();
        }
    }

    void handle_input() {
        for (;;) {
            ag::wire_utils::Reader r{{m_input_buf.data(), m_input_buf_used}};
            auto what = r.get_u32();
            auto size = r.get_u32();
            auto data = r.get_bytes(size.value_or(0));
            if (!what.has_value() || !size.has_value() || !data.has_value()) {
                return;
            }
            m_handler((VpnEasyServiceMessageType) *what, *data);
            std::memmove(m_input_buf.data(), r.get_buffer().data(), r.get_buffer().size());
            m_input_buf_used = r.get_buffer().size();
        }
    }

    bool do_write() {
        DWORD write_size = 0;
        if (m_write_pending) {
            if (!GetOverlappedResult(m_pipe, &m_olw, &write_size, FALSE)) {
                return true;
            }
            m_write_pending = false;
        }
        std::scoped_lock l{m_pending_writes_lock};
        auto &w = m_pending_writes.front();
        w.written += write_size;
        if (w.written == w.data.size()) {
            m_pending_writes.pop_front();
        }
        if (WriteFile(m_pipe, w.data.data() + w.written, w.data.size() - w.written, nullptr, &m_olw)) {

            return false;
        }
    }

    bool reconnect() {
        m_connected = false;
        m_input_buf_used = 0;
        if (!ConnectNamedPipe(m_pipe, &m_olr) && ERROR_IO_PENDING != GetLastError()
                && ERROR_PIPE_CONNECTED != GetLastError()) {
            errlog(g_logger, "ConnectNamedPipe: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
            return false;
        }
        SetEvent(m_io_event);
        return true;
    }
};

static void service_set_status(DWORD current_state) {
    SERVICE_STATUS status{
            .dwServiceType = SERVICE_WIN32_OWN_PROCESS,
            .dwCurrentState = current_state,
            .dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
    };
    SetServiceStatus(g_status_handle, &status);
}

static void WINAPI service_ctrl_handler(DWORD control) {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        SetEvent(g_shutdown_event);
        break;
    default:
        break;
    }
}

static void WINAPI service_main(DWORD /*argc*/, LPWSTR * /*argv*/) {
    g_status_handle = RegisterServiceCtrlHandlerW(L"", service_ctrl_handler);
    g_shutdown_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    service_set_status(SERVICE_RUNNING);
    WaitForSingleObject(g_shutdown_event, INFINITE);
    service_set_status(SERVICE_STOPPED);
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 3) {
        return 1;
    }

    FILE *logfile = nullptr;
    ag::UniquePtr<FILE, &fclose> logfile_guard;
    if (!_wfopen_s(&logfile, argv[1], L"w")) {
        ag::Logger::set_callback(ag::Logger::LogToFile{logfile});
        logfile_guard.reset(logfile);
    }
    ag::Logger::set_log_level(ag::LOG_LEVEL_INFO);

    g_pipe_name = argv[2];

    wchar_t svc_name[] = L"";
    SERVICE_TABLE_ENTRYW start_table[] = {
            {svc_name, service_main},
            {nullptr, nullptr},
    };

#ifndef AG_DEBUGGING_VPN_EASY_SERVICE
    if (!StartServiceCtrlDispatcherW(start_table)) {
        errlog(g_logger, "StartServiceCtrlDispatcherW: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return 3;
    }
#else
    service_main(0, nullptr);
#endif

    return 0;
}
