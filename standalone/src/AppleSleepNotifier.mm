#import "AppleSleepNotifier.h"

void AppleSleepNotifier::callback(void *refcon, io_service_t service, uint32_t messageType, void *messageArgument) {
    auto *self = (AppleSleepNotifier *) refcon;
    switch (messageType) {
    case kIOMessageCanSystemSleep:
        IOAllowPowerChange(self->m_root_port, (long) messageArgument);
        break;
    case kIOMessageSystemWillSleep:
        self->m_sleep_cb();
        IOAllowPowerChange(self->m_root_port, (long) messageArgument);
        break;
    case kIOMessageSystemWillPowerOn:
        // Early in the wakeup process, things might not be available yet.
        break;
    case kIOMessageSystemHasPoweredOn:
        self->m_wake_cb();
        break;
    default:
        break;
    }
}

AppleSleepNotifier::AppleSleepNotifier(std::function<void()> sleep_cb, std::function<void()> wake_cb)
        : m_sleep_cb{std::move(sleep_cb)}
        , m_wake_cb{std::move(wake_cb)} {
    m_run_loop_thread = std::thread([this] {
        m_root_port = IORegisterForSystemPower(this, &m_port, callback, &m_notifier);
        if (m_root_port != IO_OBJECT_NULL) {
            CFRunLoopAddSource(
                    CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(m_port), kCFRunLoopCommonModes);
        }
        CFRunLoopPerformBlock(CFRunLoopGetCurrent(), kCFRunLoopDefaultMode, ^{
          m_mutex.lock();
          m_run_loop = CFRunLoopGetCurrent();
          m_mutex.unlock();
          m_condvar.notify_one();
        });
        CFRunLoopRun();
    });
}

AppleSleepNotifier::~AppleSleepNotifier() {
    {
        std::unique_lock l{m_mutex};
        m_condvar.wait(l, [&] {
            return m_run_loop != nullptr;
        });
    }
    CFRunLoopStop(m_run_loop);
    m_run_loop_thread.join();
    if (m_root_port != IO_OBJECT_NULL) {
        IODeregisterForSystemPower(&m_notifier);
        IONotificationPortDestroy(m_port);
        IOServiceClose(m_root_port);
    }
}
