#pragma once

#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <mach/mach_init.h>

#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

#include <CoreFoundation/CoreFoundation.h>

#include <functional>
#include <mutex>
#include <thread>
#include <condition_variable>

class AppleSleepNotifier {
public:
    AppleSleepNotifier(std::function<void()> sleep_cb, std::function<void()> wake_cb);

    ~AppleSleepNotifier();

    static void callback(void *refcon, io_service_t service, uint32_t messageType, void *messageArgument);

    AppleSleepNotifier(const AppleSleepNotifier &) = delete;
    AppleSleepNotifier &operator=(const AppleSleepNotifier &) = delete;

    AppleSleepNotifier(AppleSleepNotifier &&) = delete;
    AppleSleepNotifier &operator=(AppleSleepNotifier &&) = delete;

private:
    std::condition_variable m_condvar;
    std::mutex m_mutex;
    std::thread m_run_loop_thread;
    CFRunLoopRef m_run_loop = nullptr;
    IONotificationPortRef m_port = nullptr;
    io_object_t m_notifier = IO_OBJECT_NULL;
    io_connect_t m_root_port = IO_OBJECT_NULL;
    std::function<void()> m_sleep_cb;
    std::function<void()> m_wake_cb;
};
