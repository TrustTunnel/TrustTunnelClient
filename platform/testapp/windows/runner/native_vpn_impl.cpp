#include "native_vpn_impl.h"
#include "vpn/vpn_easy.h"


namespace {
    void state_changed_handler(void *arg, int state) {
        auto *ctx = static_cast<NativeVpnImpl *>(arg);
        ctx->NotifyStateChanged(state);
    }
}

void NativeVpnImpl::NotifyStateChanged(int state) {
    m_dispatcher->RunOnUIThread([this, state]() {
        m_callbacks.OnStateChanged(
            state,
            []() { /*do nothing*/ },
            [this](const FlutterError& error) {
                warnlog(m_logger, "Faield to set updated VPN state: {}:{}", error.code(), error.message());
            }
        );
    });
}

NativeVpnImpl::NativeVpnImpl(IUIThreadDispatcher *dispatcher, FlutterCallbacks &&callbacks)
    : m_callbacks(std::move(callbacks))
    , m_dispatcher(dispatcher) {
}

std::optional<FlutterError> NativeVpnImpl::Start(const std::string &config) {
    vpn_easy_start(config.c_str(), state_changed_handler, this);
    // Always return no error because flutter treats them as exceptions
    // and pigeon doesn't allow to handle them in a general way
    return std::nullopt;
}

std::optional<FlutterError> NativeVpnImpl::Stop() {
    vpn_easy_stop();
    return std::nullopt;
}