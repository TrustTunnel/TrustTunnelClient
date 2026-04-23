#include "vpn/vpn_easy_service.h"
#include "vpn/vpn_easy.h"

#include <atomic>
#include <cstdio>
#include <functional>
#include <string>

#include "common/defs.h"
#include "common/logger.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "common/system_error.h"
#include "pipe.h"
#include "vpn/trusttunnel/connection_info.h"
#include "vpn/vpn.h"

using ag::vpn_easy::PipeServer;

static ag::Logger g_logger{"VPN_EASY_SERVICE"};

static std::wstring g_pipe_name;
static SERVICE_STATUS_HANDLE g_status_handle;
static HANDLE g_shutdown_event;
static vpn_easy_t *g_vpn;
static std::atomic<int32_t> g_last_state{ag::VPN_SS_DISCONNECTED};

/// Send a `VPN_EASY_SVC_MSG_STATE_CHANGED` message with the given state value.
static void send_state(PipeServer &server, int32_t state) {
    uint32_t net_state = htonl(static_cast<uint32_t>(state));
    server.send(VPN_EASY_SVC_MSG_STATE_CHANGED, {reinterpret_cast<const uint8_t *>(&net_state), sizeof(net_state)});
}

/// Handle an incoming pipe message from a client.
static void pipe_handler(PipeServer &server, VpnEasyServiceMessageType what, ag::Uint8View data) {
    switch (what) {
    case VPN_EASY_SVC_MSG_START: {
        if (g_vpn != nullptr) {
            infolog(g_logger, "VPN already running, stopping before restart");
            vpn_easy_stop_ex(g_vpn);
            g_vpn = nullptr;
        }
        std::string toml_config(reinterpret_cast<const char *>(data.data()), data.size());
        infolog(g_logger, "Starting VPN client");
        g_vpn = vpn_easy_start_ex(
                toml_config.c_str(),
                [](void *arg, int state) {
                    g_last_state.store(state, std::memory_order_relaxed);
                    send_state(*static_cast<PipeServer *>(arg), state);
                },
                &server,
                [](void *arg, void *connection_info) {
                    std::string json =
                            ag::ConnectionInfo::to_json(static_cast<ag::VpnConnectionInfoEvent *>(connection_info));
                    static_cast<PipeServer *>(arg)->send(VPN_EASY_SVC_MSG_CONNECTION_INFO,
                            {reinterpret_cast<const uint8_t *>(json.data()), json.size()});
                },
                &server);
        if (g_vpn == nullptr) {
            warnlog(g_logger, "vpn_easy_start_ex failed");
            g_last_state.store(ag::VPN_SS_DISCONNECTED, std::memory_order_relaxed);
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
    case VPN_EASY_SVC_MSG_GET_LAST_STATE: {
        send_state(server, g_last_state.load(std::memory_order_relaxed));
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

    auto sd = PipeServer::for_authenticated_users();
    PipeServer server{g_pipe_name.c_str(), g_shutdown_event,
            [&server](VpnEasyServiceMessageType what, ag::Uint8View data) {
                pipe_handler(server, what, data);
            },
            sd.get()};

    service_set_status(SERVICE_RUNNING);
    server.loop();

    if (g_vpn != nullptr) {
        infolog(g_logger, "Shutting down: stopping VPN client");
        vpn_easy_stop_ex(g_vpn);
        g_vpn = nullptr;
    }

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
