#include "vpn/vpn_easy_service.h"
#include "vpn/vpn_easy.h"

#include <cstdio>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

#include "common/defs.h"
#include "common/logger.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "common/system_error.h"
#include "vpn/trusttunnel/connection_info.h"
#include "vpn/trusttunnel/persistent_ring_buffer.h"
#include "vpn/vpn.h"
#include "vpn/file_logger.h"
#include "vpn_easy_log.h"
#include "vpn_easy_pipe.h"
#include "scoped_file_lock.h"

using ag::vpn_easy::PipeServer;

static ag::Logger g_logger{"VPN_EASY_SERVICE"};

static std::wstring g_pipe_name;
static SERVICE_STATUS_HANDLE g_status_handle;
static HANDLE g_shutdown_event;
static vpn_easy_t *g_vpn;
static std::optional<ag::PersistentRingBuffer> g_ring_buffer;
static std::filesystem::path g_ring_buffer_path;
static std::mutex g_state_mutex;
static std::optional<ag::FileLogger> g_file_logger;
/// Current VPN session state. Updated by `send_state()` and reset on VPN stop.
static int32_t g_current_vpn_state = ag::VPN_SS_DISCONNECTED;

static void send_state_message(PipeServer &server, int32_t state) {
    uint32_t net_state = htonl(static_cast<uint32_t>(state));
    server.send(VPN_EASY_SVC_MSG_STATE_CHANGED, {reinterpret_cast<const uint8_t *>(&net_state), sizeof(net_state)});
}

/// Send a `VPN_EASY_SVC_MSG_STATE_CHANGED` message with the given state value.
static void send_state(PipeServer &server, int32_t state) {
    std::scoped_lock lock{g_state_mutex};
    g_current_vpn_state = state;
    send_state_message(server, state);
}

/// Handle an incoming pipe message from a client.
static void pipe_handler(PipeServer &server, VpnEasyServiceMessageType what, ag::Uint8View data) {
    switch (what) {
    case VPN_EASY_SVC_MSG_START: {
        if (g_vpn != nullptr) {
            infolog(g_logger, "VPN already running, stopping before restart");
            vpn_easy_stop_ex(g_vpn);
            g_vpn = nullptr;
            std::scoped_lock lock{g_state_mutex};
            g_current_vpn_state = ag::VPN_SS_DISCONNECTED;
        }
        std::string toml_config(reinterpret_cast<const char *>(data.data()), data.size());
        infolog(g_logger, "Starting VPN client");
        g_vpn = vpn_easy_start_ex(
                toml_config.c_str(),
                [](void *arg, int state) {
                    send_state(*static_cast<PipeServer *>(arg), state);
                },
                &server,
                [](void *arg, void *connection_info) {
                    std::string json =
                            ag::ConnectionInfo::to_json(static_cast<ag::VpnConnectionInfoEvent *>(connection_info));
                    // Persist to ring buffer if configured, with cross-process mutex
                    if (g_ring_buffer.has_value()) {
                        ag::vpn_easy::ScopedFileLock lock(g_ring_buffer_path);
                        if (lock) {
                            g_ring_buffer->append(json);
                        }
                    }
                    static_cast<PipeServer *>(arg)->send(VPN_EASY_SVC_MSG_CONNECTION_INFO,
                            {reinterpret_cast<const uint8_t *>(json.data()), json.size()});
                },
                &server);
        if (g_vpn == nullptr) {
            warnlog(g_logger, "vpn_easy_start_ex failed");
            send_state(server, ag::VPN_SS_DISCONNECTED);
        }
        break;
    }
    case VPN_EASY_SVC_MSG_STOP: {
        if (g_vpn == nullptr) {
            infolog(g_logger, "VPN already stopped, ignoring STOP");
            return;
        }
        infolog(g_logger, "Stopping VPN client");
        vpn_easy_stop_ex(g_vpn);
        g_vpn = nullptr;
        break;
    }
    case VPN_EASY_SVC_MSG_QUERY_STATE: {
        std::scoped_lock lock{g_state_mutex};
        infolog(g_logger, "Client queried current state: {}", g_current_vpn_state);
        send_state_message(server, g_current_vpn_state);
        break;
    }
    case VPN_EASY_SVC_MSG_STATE_CHANGED:
    case VPN_EASY_SVC_MSG_CONNECTION_INFO:
        warnlog(g_logger, "Ignoring server-to-client message type: {}", static_cast<int>(what));
        break;
    default:
        warnlog(g_logger, "Unknown message type: {}", static_cast<int>(what));
        break;
    }
}

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

    service_set_status(SERVICE_START_PENDING);

    PipeServer server{g_pipe_name.c_str(), g_shutdown_event,
            [&server](VpnEasyServiceMessageType what, ag::Uint8View data) {
                pipe_handler(server, what, data);
            },
            PipeServer::for_authenticated_users().get()};

    service_set_status(SERVICE_RUNNING);
    server.loop();

    if (g_vpn != nullptr) {
        infolog(g_logger, "Shutting down: stopping VPN client");
        {
            std::scoped_lock lock{g_state_mutex};
            g_current_vpn_state = ag::VPN_SS_DISCONNECTED;
        }
        vpn_easy_stop_ex(g_vpn);
        g_vpn = nullptr;
    }

    service_set_status(SERVICE_STOPPED);
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 4) {
        return 1;
    }

    // argv[1] is the logs directory; the service writes its rotating "service" log family there.
    std::filesystem::path logs_dir = argv[1];
    auto log_sync = std::make_shared<ag::vpn_easy::WindowsFileLoggerSync>();
    g_file_logger.emplace(logs_dir, ag::vpn_easy::SERVICE_LOG_BASE, ag::FileLogger::DEFAULT_MAX_FILE_SIZE,
            ag::FileLogger::DEFAULT_ARCHIVE_COUNT, log_sync);
    g_file_logger->install();
    ag::Logger::set_log_level(ag::LOG_LEVEL_INFO);

    g_pipe_name = argv[2];

    {
        g_ring_buffer_path = std::filesystem::path(argv[3]);
        g_ring_buffer.emplace(g_ring_buffer_path);
    }

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
