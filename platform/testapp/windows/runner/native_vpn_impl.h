#pragma once
#include <common/logger.h>

#include <string>
#include <memory>

#include "pigeon/native_communication.h"
#include "ui_thread_dispatcher.h"

class NativeVpnImpl : public NativeVpnInterface {
public:
    NativeVpnImpl(IUIThreadDispatcher *dispatcher,
                  FlutterCallbacks &&callbacks,
                  std::string ring_buffer_path,
                  std::wstring service_name,
                  std::wstring pipe_name);
    ~NativeVpnImpl() override;

    std::optional<FlutterError> Start(const std::string &config) override;
    std::optional<FlutterError> Stop() override;

    void NotifyStateChanged(int state);
    void NotifyConnectionInfo(const std::string &json);

private:
    ag::Logger m_logger{"NativeVpnImpl"};
    FlutterCallbacks m_callbacks;
    IUIThreadDispatcher *m_dispatcher;
    std::string m_ring_buffer_path;
    std::wstring m_service_name;
    std::wstring m_pipe_name;
    bool m_is_started = false;
};