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
