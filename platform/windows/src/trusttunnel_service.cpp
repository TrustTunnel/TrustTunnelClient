#include "trusttunnel/trusttunnel_service.h"
#include "trusttunnel/trusttunnel.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <magic_enum/magic_enum.hpp>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "client_authenticator.h"
#include "common/defs.h"
#include "common/logger.h"
#include "common/system_error.h"
#include "scoped_file_lock.h"
#include "service_registry.h"
#include "trusttunnel_log.h"
#include "trusttunnel_pipe.h"
#include "vpn/file_logger.h"
#include "vpn/trusttunnel/connection_info.h"
#include "vpn/trusttunnel/persistent_ring_buffer.h"
#include "vpn/vpn.h"

using ag::trusttunnel_windows::PipeServer;
using ag::trusttunnel_windows::RegistryValue;
using AutoScHandle = ag::UniquePtr<std::remove_pointer_t<SC_HANDLE>, &CloseServiceHandle>;
using namespace std::chrono;

static ag::Logger g_logger{"TRUSTTUNNEL_SERVICE"};

static std::wstring g_service_name;
static std::wstring g_pipe_name;
static SERVICE_STATUS_HANDLE g_status_handle;
static HANDLE g_shutdown_event;
static trusttunnel_t *g_vpn;
static std::optional<ag::PersistentRingBuffer> g_ring_buffer;
static std::filesystem::path g_ring_buffer_path;
static std::optional<ag::FileLogger> g_file_logger;
static int32_t g_current_vpn_state = ag::VPN_SS_DISCONNECTED;

static void send_state(PipeServer &server, int32_t state) {
    g_current_vpn_state = state;
    uint32_t net_state = htonl(static_cast<uint32_t>(state));
    server.send(TRUSTTUNNEL_SVC_MSG_STATE_CHANGED, {reinterpret_cast<const uint8_t *>(&net_state), sizeof(net_state)});
}

/// Destroy the current VPN client, if any. Must be called on the pipe loop thread.
static void release_vpn() {
    if (g_vpn != nullptr) {
        trusttunnel_stop_ex(std::exchange(g_vpn, nullptr));
    }
}

static RegistryValue saved_config() {
    return ag::trusttunnel_windows::ServiceRegistry{g_service_name}.saved_config();
}

/// Save `toml` as the configuration to connect with on startup.
static void save_config(std::string_view toml) {
    if (int32_t err = saved_config().write_binary(toml); err != 0) {
        warnlog(g_logger, "Failed to save the VPN configuration ({})", err);
        return;
    }
    infolog(g_logger, "VPN configuration saved");
}

/**
 * The connection with the saved configuration made when the service starts at boot. Until it first
 * succeeds, a failed attempt is retried for a while, since the network may still be coming up.
 * All methods must be called on the pipe loop thread.
 */
class StartupConnection {
public:
    explicit StartupConnection(PipeServer &server)
            : m_server{server} {
    }

    ~StartupConnection();

    StartupConnection(const StartupConnection &) = delete;
    StartupConnection &operator=(const StartupConnection &) = delete;
    StartupConnection(StartupConnection &&) = delete;
    StartupConnection &operator=(StartupConnection &&) = delete;

    /** Make the first attempt. */
    void start();

    /**
     * Stop retrying, as the connection succeeded or a client took over. A client waiting for the
     * next attempt is told the VPN is disconnected.
     */
    void stop();

    /** Schedule the next attempt after a failed one. Return false once retrying is over. */
    bool retry();

private:
    static constexpr auto RETRY_PERIOD = minutes{2};
    static constexpr auto RETRY_INTERVAL = seconds{5};

    void attempt();
    static void CALLBACK on_timer(PTP_CALLBACK_INSTANCE instance, void *context, PTP_TIMER timer);

    PipeServer &m_server;
    PTP_TIMER m_timer = nullptr;
    /** Set while the connection has not succeeded and may still be retried. */
    std::optional<steady_clock::time_point> m_deadline;
};

static std::optional<StartupConnection> g_startup_connection;

/// Report a stopped VPN client, or a pending retry, which clients must still be able to stop.
static void report_vpn_stopped(PipeServer &server) {
    send_state(server, g_startup_connection->retry() ? ag::VPN_SS_WAITING_RECOVERY : ag::VPN_SS_DISCONNECTED);
}

/// Start the VPN client. Must be called on the pipe loop thread while no VPN client is running.
static void start_vpn(PipeServer &server, const std::string &toml_config) {
    infolog(g_logger, "Starting VPN client");
    g_vpn = trusttunnel_start_ex(
            toml_config.c_str(),
            [](void *arg, int state) {
                // Runs on the VPN client's event loop thread; everything else runs on the
                // pipe loop thread, so the work is deferred there.
                PipeServer *server = static_cast<PipeServer *>(arg);
                server->post([server, state]() {
                    if (state == ag::VPN_SS_CONNECTED) {
                        g_startup_connection->stop();
                    }
                    if (state != ag::VPN_SS_DISCONNECTED) {
                        send_state(*server, state);
                        return;
                    }
                    // Release the client promptly so that the OS tunnel adapter and its
                    // worker threads do not linger for the lifetime of the service.
                    infolog(g_logger, "VPN disconnected, releasing VPN client");
                    release_vpn();
                    report_vpn_stopped(*server);
                });
            },
            &server,
            [](void *arg, void *connection_info) {
                std::string json =
                        ag::ConnectionInfo::to_json(static_cast<ag::VpnConnectionInfoEvent *>(connection_info));
                // Persist to ring buffer if configured, with cross-process mutex
                if (g_ring_buffer.has_value()) {
                    ag::trusttunnel_windows::ScopedFileLock lock(g_ring_buffer_path);
                    if (lock) {
                        g_ring_buffer->append(json);
                    }
                }
                static_cast<PipeServer *>(arg)->send(TRUSTTUNNEL_SVC_MSG_CONNECTION_INFO,
                        {reinterpret_cast<const uint8_t *>(json.data()), json.size()});
            },
            &server);
    if (g_vpn == nullptr) {
        warnlog(g_logger, "trusttunnel_start_ex failed");
        report_vpn_stopped(server);
    }
}

StartupConnection::~StartupConnection() {
    if (m_timer != nullptr) {
        SetThreadpoolTimer(m_timer, nullptr, 0, 0);
        WaitForThreadpoolTimerCallbacks(m_timer, TRUE);
        CloseThreadpoolTimer(m_timer);
    }
}

void StartupConnection::start() {
    m_timer = CreateThreadpoolTimer(&on_timer, this, nullptr);
    if (m_timer == nullptr) {
        DWORD error = GetLastError();
        errlog(g_logger, "CreateThreadpoolTimer: {} ({})", error, ag::sys::strerror(error));
        return;
    }
    m_deadline = steady_clock::now() + RETRY_PERIOD;
    attempt();
}

void StartupConnection::stop() {
    if (!m_deadline.has_value()) {
        return;
    }
    m_deadline.reset();
    SetThreadpoolTimer(m_timer, nullptr, 0, 0);
    if (g_vpn == nullptr) {
        send_state(m_server, ag::VPN_SS_DISCONNECTED);
    }
}

bool StartupConnection::retry() {
    if (!m_deadline.has_value()) {
        return false;
    }
    if (steady_clock::now() >= *m_deadline) {
        warnlog(g_logger, "Failed to connect on startup, giving up");
        m_deadline.reset();
        return false;
    }

    infolog(g_logger, "Retrying to connect on startup in {} s", RETRY_INTERVAL.count());
    using FileTimeTicks = duration<int64_t, std::ratio<1, 10'000'000>>;
    // A negative due time is relative to now.
    ULARGE_INTEGER due{.QuadPart = static_cast<ULONGLONG>(-FileTimeTicks{RETRY_INTERVAL}.count())};
    FILETIME due_time{.dwLowDateTime = due.LowPart, .dwHighDateTime = due.HighPart};
    SetThreadpoolTimer(m_timer, &due_time, 0, 0);
    return true;
}

void StartupConnection::attempt() {
    // A client may have taken over while the attempt was being scheduled.
    if (!m_deadline.has_value() || g_vpn != nullptr) {
        return;
    }
    std::optional<std::string> toml_config = saved_config().read_binary();
    if (!toml_config) {
        infolog(g_logger, "No saved VPN configuration, not connecting on startup");
        stop();
        return;
    }
    infolog(g_logger, "Connecting on startup with the saved VPN configuration");
    start_vpn(m_server, *toml_config);
}

void CALLBACK StartupConnection::on_timer(PTP_CALLBACK_INSTANCE /*instance*/, void *context, PTP_TIMER /*timer*/) {
    auto *self = static_cast<StartupConnection *>(context);
    self->m_server.post([self]() {
        self->attempt();
    });
}

/// Switch the service between starting at boot and starting on demand.
static void set_connect_on_startup(bool enabled) {
    AutoScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    AutoScHandle svc{scm ? OpenServiceW(scm.get(), g_service_name.c_str(), SERVICE_CHANGE_CONFIG) : nullptr};
    if (!svc
            || !ChangeServiceConfigW(svc.get(), SERVICE_NO_CHANGE, enabled ? SERVICE_AUTO_START : SERVICE_DEMAND_START,
                    SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
        DWORD error = GetLastError();
        warnlog(g_logger, "Failed to change the service start type: {} ({})", error, ag::sys::strerror(error));
        return;
    }
    infolog(g_logger, "Connect on startup {}", enabled ? "enabled" : "disabled");
}

/// Report whether the SCM started the service automatically, that is at boot.
static bool started_at_boot() {
    SERVICE_START_REASON *reason = nullptr;
    if (!QueryServiceDynamicInformation(
                g_status_handle, SERVICE_DYNAMIC_INFORMATION_LEVEL_START_REASON, reinterpret_cast<void **>(&reason))) {
        DWORD error = GetLastError();
        warnlog(g_logger, "QueryServiceDynamicInformation: {} ({})", error, ag::sys::strerror(error));
        return false;
    }
    bool at_boot = (reason->dwReason & (SERVICE_START_REASON_AUTO | SERVICE_START_REASON_DELAYEDAUTO)) != 0;
    LocalFree(reason);
    return at_boot;
}

/// Handle an incoming pipe message from a client.
static void pipe_handler(PipeServer &server, TrusttunnelServiceMessageType what, ag::Uint8View data) {
    switch (what) {
    case TRUSTTUNNEL_SVC_MSG_START: {
        if (g_vpn != nullptr) {
            warnlog(g_logger, "VPN is already running, ignoring START");
            break;
        }
        g_startup_connection->stop();
        std::string toml_config(reinterpret_cast<const char *>(data.data()), data.size());
        // Stored before connecting, so the configuration survives a failed connection.
        save_config(toml_config);
        start_vpn(server, toml_config);
        break;
    }
    case TRUSTTUNNEL_SVC_MSG_STOP: {
        g_startup_connection->stop();
        if (g_vpn == nullptr) {
            infolog(g_logger, "VPN already stopped, ignoring STOP");
            break;
        }
        infolog(g_logger, "Stopping VPN client");
        release_vpn();
        break;
    }
    case TRUSTTUNNEL_SVC_MSG_QUERY_STATE: {
        infolog(g_logger, "Client queried current state: {}", g_current_vpn_state);
        send_state(server, g_current_vpn_state);
        break;
    }
    case TRUSTTUNNEL_SVC_MSG_CLEAR_LOGS: {
        infolog(g_logger, "Clearing service logs on client request");
        if (g_file_logger.has_value()) {
            g_file_logger->clear_logs();
        }
        break;
    }
    case TRUSTTUNNEL_SVC_MSG_UPDATE_CONFIG: {
        if (!data.empty()) {
            // A running VPN client keeps its configuration until the next start.
            save_config({reinterpret_cast<const char *>(data.data()), data.size()});
            break;
        }
        if (int32_t err = saved_config().remove(); err != 0) {
            warnlog(g_logger, "Failed to remove the saved VPN configuration ({})", err);
            break;
        }
        infolog(g_logger, "Saved VPN configuration removed");
        break;
    }
    case TRUSTTUNNEL_SVC_MSG_SET_CONNECT_ON_STARTUP: {
        if (data.size() != 1) {
            warnlog(g_logger, "Ignoring SET_CONNECT_ON_STARTUP of {} bytes", data.size());
            break;
        }
        set_connect_on_startup(data[0] != 0);
        break;
    }
    case TRUSTTUNNEL_SVC_MSG_STATE_CHANGED:
    case TRUSTTUNNEL_SVC_MSG_CONNECTION_INFO:
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

static void WINAPI service_main(DWORD /*argc*/, LPWSTR *argv) {
    // The SCM always passes the service name as the first ServiceMain argument.
    g_service_name = argv[0];
    g_status_handle = RegisterServiceCtrlHandlerW(g_service_name.c_str(), service_ctrl_handler);
    g_shutdown_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    service_set_status(SERVICE_START_PENDING);

    // The authenticator is wired into the server via a validator callback, so it must outlive
    // `server`. The service's own image path and signature are the trust anchor for every client.
    ag::trusttunnel_windows::ClientAuthenticator authenticator{ag::trusttunnel_windows::ProcessInfo::current(),
            ag::trusttunnel_windows::AuthenticodeSignature::of_current_process()};
    auto peer_validator = [&authenticator](HANDLE pipe) {
        ag::trusttunnel_windows::ClientValidationDecision decision = authenticator.validate(pipe);
        if (decision != ag::trusttunnel_windows::ClientValidationDecision::ALLOWED) {
            warnlog(g_logger, "Rejecting pipe client: {}", magic_enum::enum_name(decision));
        }
        return decision == ag::trusttunnel_windows::ClientValidationDecision::ALLOWED;
    };

    const RegistryValue published_pipe_name = ag::trusttunnel_windows::ServiceRegistry{g_service_name}.pipe_name();

    PipeServer server{g_pipe_name.c_str(), g_shutdown_event,
            [&server](TrusttunnelServiceMessageType what, ag::Uint8View data) {
                pipe_handler(server, what, data);
            },
            PipeServer::for_authenticated_users().get(), std::move(peer_validator)};

    // Publish the effective pipe name after the pipe exists and before reporting RUNNING, so a
    // client that observes the running state is guaranteed to find the name. A service that
    // cannot publish must not serve undiscoverable clients, so this is a hard startup failure.
    if (int32_t err = published_pipe_name.write_string(g_pipe_name); err != 0) {
        errlog(g_logger, "Failed to publish the pipe name ({}); stopping", err);
        service_set_status(SERVICE_STOPPED);
        return;
    }

    service_set_status(SERVICE_RUNNING);

    // Destroyed before `server`, since its timer callback posts to it.
    g_startup_connection.emplace(server);
    // Started at boot only when connecting on startup is enabled, see `set_connect_on_startup()`.
    if (started_at_boot()) {
        server.post([]() {
            g_startup_connection->start();
        });
    }

    server.loop();
    g_startup_connection.reset();

    if (int32_t err = published_pipe_name.remove(); err != 0) {
        warnlog(g_logger, "Failed to delete the published pipe name ({})", err);
    }

    if (g_vpn != nullptr) {
        infolog(g_logger, "Shutting down: stopping VPN client");
        release_vpn();
    }

    service_set_status(SERVICE_STOPPED);
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 4) {
        return 1;
    }

    // argv[1] is the logs directory; the service writes its rotating "service" log family there.
    std::filesystem::path logs_dir = argv[1];
    auto log_sync = std::make_shared<ag::trusttunnel_windows::WindowsFileLoggerSync>();
    g_file_logger.emplace(logs_dir, ag::trusttunnel_windows::SERVICE_LOG_BASE, ag::FileLogger::DEFAULT_MAX_FILE_SIZE,
            ag::FileLogger::DEFAULT_ARCHIVE_COUNT, log_sync);
    g_file_logger->install();
    ag::Logger::set_log_level(ag::LOG_LEVEL_INFO);

    // argv[2] is the provisioned pipe name: empty means "generate a fresh one per start".
    g_pipe_name = argv[2];
    if (g_pipe_name.empty()) {
        std::optional<std::wstring> generated = ag::trusttunnel_windows::generate_pipe_name();
        if (!generated.has_value()) {
            errlog(g_logger, "Failed to generate a pipe name");
            return 2;
        }
        g_pipe_name = std::move(*generated);
    }

    {
        g_ring_buffer_path = std::filesystem::path(argv[3]);
        g_ring_buffer.emplace(g_ring_buffer_path);
    }

    wchar_t svc_name[] = L"";
    SERVICE_TABLE_ENTRYW start_table[] = {
            {svc_name, service_main},
            {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(start_table)) {
        errlog(g_logger, "StartServiceCtrlDispatcherW: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return 3;
    }

    return 0;
}
