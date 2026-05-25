#include "native_vpn_impl.h"
#include "vpn/vpn.h"
#include "vpn/vpn_easy.h"
#include "vpn/vpn_easy_service.h"

#include <filesystem>

static void s_notify_state_changed(void *arg, int state) {
    static_cast<NativeVpnImpl *>(arg)->NotifyStateChanged(state);
}

static void s_notify_connection_info(void *arg, const char *json) {
    static_cast<NativeVpnImpl *>(arg)->NotifyConnectionInfo(std::string(json));
}

NativeVpnImpl::NativeVpnImpl(IUIThreadDispatcher *dispatcher, FlutterCallbacks &&callbacks,
        std::string ring_buffer_path, std::wstring service_name, std::wstring pipe_name)
        : m_callbacks(std::move(callbacks))
        , m_dispatcher(dispatcher)
        , m_ring_buffer_path(std::move(ring_buffer_path))
        , m_service_name(std::move(service_name))
        , m_pipe_name(std::move(pipe_name)) {
    // Read all persisted connection info records on construction (before VPN is started)
    vpn_easy_service_read_all_connection_info(
            m_ring_buffer_path.c_str(), s_notify_connection_info, this);

    // Try to attach to a running service to detect current VPN state.
    int32_t attach_result = attach_service();

    if (attach_result != 0) {
        infolog(m_logger, "VPN service not running (attach result: {}), assuming DISCONNECTED", attach_result);
    } else {
        infolog(m_logger, "Attached to running VPN service");
    }
}

NativeVpnImpl::~NativeVpnImpl() {
    vpn_easy_service_detach();
}

void NativeVpnImpl::NotifyStateChanged(int state) {
    m_dispatcher->RunOnUIThread([this, state]() {
        m_callbacks.OnStateChanged(
                state, []() { /*do nothing*/ },
                [this](const FlutterError &error) {
                    warnlog(m_logger, "Failed to set updated VPN state: {}:{}", error.code(), error.message());
                });
    });
}

void NativeVpnImpl::NotifyConnectionInfo(const std::string &json) {
    m_dispatcher->RunOnUIThread([this, json]() {
        m_callbacks.OnConnectionInfo(
                json, []() { /*do nothing*/ },
                [this](const FlutterError &error) {
                    warnlog(m_logger, "Failed to set connection info: {}:{}", error.code(), error.message());
                });
    });
}

int32_t NativeVpnImpl::install_service() {
    wchar_t exe_path[MAX_PATH];
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    std::filesystem::path exe_dir = std::filesystem::path(exe_path).parent_path();
    std::wstring service_exe = (exe_dir / L"vpn_easy_service.exe").wstring();
    std::wstring log_path = exe_dir / L"vpn_easy_service.log";
    std::wstring ring_buffer_path_w;
    int ring_buffer_path_len = MultiByteToWideChar(CP_UTF8, 0, m_ring_buffer_path.c_str(), -1, nullptr, 0);
    if (ring_buffer_path_len > 0) {
        ring_buffer_path_w.assign(ring_buffer_path_len - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, m_ring_buffer_path.c_str(), -1, &ring_buffer_path_w[0], ring_buffer_path_len);
    }

    return vpn_easy_service_install(service_exe.c_str(), log_path.c_str(), m_pipe_name.c_str(),
            m_service_name.c_str(), L"TrustTunnel VPN Service",
            L"Provides VPN connectivity for the TrustTunnel client.", ring_buffer_path_w.c_str());
}

int32_t NativeVpnImpl::attach_service() {
    return vpn_easy_service_attach(
            m_service_name.c_str(), m_pipe_name.c_str(), 
            s_notify_state_changed, this, s_notify_connection_info, this);
}

int32_t NativeVpnImpl::start_service(const std::string &config) {
    return vpn_easy_service_start(
            m_service_name.c_str(), m_pipe_name.c_str(), config.c_str(),
            s_notify_state_changed, this, s_notify_connection_info, this);
}

std::optional<FlutterError> NativeVpnImpl::Start(const std::string &config) {
    int32_t start_result = start_service(config);

    if (start_result == VPN_EASY_SVC_ERR_NO_SUCH_SERVICE) {
        // Service not installed — install once (needs admin), then retry.
        int32_t install_result = install_service();
        if (install_result != 0) {
            warnlog(m_logger, "Failed to install VPN service: {}", install_result);
            return FlutterError("SERVICE_INSTALL", "Failed to install VPN service");
        }

        start_result = start_service(config);
    }

    if (start_result != 0) {
        warnlog(m_logger, "Failed to start VPN service: {}", start_result);
        return FlutterError("SERVICE_START", "Failed to start VPN service");
    }
    return std::nullopt;
}

std::optional<FlutterError> NativeVpnImpl::Stop() {
    int32_t stop_result = vpn_easy_service_stop(m_service_name.c_str(), m_pipe_name.c_str());
    if (stop_result != 0) {
        warnlog(m_logger, "Failed to stop VPN service: {}", stop_result);
    }
    return std::nullopt;
}