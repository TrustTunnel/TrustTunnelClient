#pragma once
#include <common/logger.h>

#include "pigeon/native_communication.h"
#include "ui_thread_dispatcher.h"

class NativeVpnImpl : public NativeVpnInterface {
public:
    NativeVpnImpl(IUIThreadDispatcher *dispatcher, FlutterCallbacks &&callbacks);
    std::optional<FlutterError> Start(const std::string &config) override;
    std::optional<FlutterError> Stop() override;
    void NotifyStateChanged(int state);
private:
    ag::Logger m_logger{"NativeVpnImpl"};

    FlutterCallbacks m_callbacks;
    IUIThreadDispatcher *m_dispatcher;
};