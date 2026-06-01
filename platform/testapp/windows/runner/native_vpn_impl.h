#pragma once
#include <common/logger.h>

#include <filesystem>
#include <memory>
#include <string>

#include "pigeon/native_communication.h"
#include "ui_thread_dispatcher.h"

class NativeVpnImpl : public NativeVpnInterface {
public:
    NativeVpnImpl(IUIThreadDispatcher *dispatcher, FlutterCallbacks &&callbacks, std::filesystem::path ring_buffer_path,
            std::wstring service_name, std::wstring pipe_name);
    ~NativeVpnImpl() override;

    std::optional<FlutterError> Start(const std::string &config) override;
    std::optional<FlutterError> Stop() override;

    void NotifyStateChanged(int state);
    void NotifyConnectionInfo(const std::string &json);

private:
    ag::Logger m_logger{"NativeVpnImpl"};
    FlutterCallbacks m_callbacks;
    IUIThreadDispatcher *m_dispatcher;
    std::filesystem::path m_ring_buffer_path;
    std::wstring m_service_name;
    std::wstring m_pipe_name;

    /** Install the Windows service. Returns 0 on success, error code on failure. */
    int32_t install_service();
    /** Uninstall the Windows service. Returns 0 on success, error code on failure. */
    int32_t uninstall_service();
    /** Attach to a running Windows service. Returns 0 on success, error code on failure. */
    int32_t attach_service();
    /** Start the Windows service. Returns 0 on success, error code on failure. */
    int32_t start_service(const std::string &config);
};