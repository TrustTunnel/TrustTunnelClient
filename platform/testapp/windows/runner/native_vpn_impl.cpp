#include "native_vpn_impl.h"
#include "vpn/vpn_easy.h"
#include "vpn/vpn_easy_service.h"

#include <filesystem>

namespace {
void state_changed_handler(void *arg, int state) {
    auto *ctx = static_cast<NativeVpnImpl *>(arg);
    ctx->NotifyStateChanged(state);
}
} // namespace

NativeVpnImpl::NativeVpnImpl(IUIThreadDispatcher *dispatcher,
                             FlutterCallbacks &&callbacks,
                             std::string ring_buffer_path,
                             std::wstring service_name,
                             std::wstring pipe_name)
        : m_callbacks(std::move(callbacks))
        , m_dispatcher(dispatcher)
        , m_ring_buffer_path(std::move(ring_buffer_path))
        , m_service_name(std::move(service_name))
        , m_pipe_name(std::move(pipe_name)) {
    // Read all persisted connection info records on construction (before VPN is started)
    vpn_easy_read_all_connection_info(
            m_ring_buffer_path.c_str(),
            [](void *arg, const char *json) {
                auto *self = static_cast<NativeVpnImpl *>(arg);
                self->NotifyConnectionInfo(std::string(json));
            },
            this);
}

NativeVpnImpl::~NativeVpnImpl() {
    if (m_is_started) {
        vpn_easy_service_stop(m_service_name.c_str(), m_pipe_name.c_str());
    }
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

std::optional<FlutterError> NativeVpnImpl::Start(const std::string &config) {
    wchar_t exe_path[MAX_PATH];
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    std::filesystem::path exe_dir = std::filesystem::path(exe_path).parent_path();
    std::wstring service_exe = (exe_dir / L"vpn_easy_service.exe").wstring();

    // Try to install the service (idempotent — fails with VPN_EASY_SVC_ERR_SERVICE_EXISTS if already installed)
    std::wstring log_path = exe_dir / L"vpn_easy_service.log";
    std::wstring ring_buffer_path_w(m_ring_buffer_path.begin(), m_ring_buffer_path.end());

    int32_t install_result = vpn_easy_service_install(
            service_exe.c_str(),
            log_path.c_str(),
            m_pipe_name.c_str(),
            m_service_name.c_str(),
            L"TrustTunnel VPN Service",
            L"Provides VPN connectivity for the TrustTunnel client.",
            ring_buffer_path_w.c_str());

    if (install_result != 0 && install_result != VPN_EASY_SVC_ERR_SERVICE_EXISTS) {
        warnlog(m_logger, "Failed to install VPN service: {}", install_result);
        return FlutterError("SERVICE_INSTALL", "Failed to install VPN service");
    }

    int32_t start_result = vpn_easy_service_start(
            m_service_name.c_str(),
            m_pipe_name.c_str(),
            config.c_str(),
            [](void *arg, int state) {
                static_cast<NativeVpnImpl *>(arg)->NotifyStateChanged(state);
            },
            this,
            [](void *arg, const char *json) {
                static_cast<NativeVpnImpl *>(arg)->NotifyConnectionInfo(std::string(json));
            },
            this);

    if (start_result != 0) {
        warnlog(m_logger, "Failed to start VPN service: {}", start_result);
        return FlutterError("SERVICE_START", "Failed to start VPN service");
    }

    m_is_started = true;
    return std::nullopt;
}

std::optional<FlutterError> NativeVpnImpl::Stop() {
    if (!m_is_started) {
        return std::nullopt;
    }

    int32_t stop_result = vpn_easy_service_stop(m_service_name.c_str(), m_pipe_name.c_str());
    if (stop_result != 0) {
        warnlog(m_logger, "Failed to stop VPN service: {}", stop_result);
    }

    m_is_started = false;
    return std::nullopt;
}