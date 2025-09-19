#pragma once

/**
 * Helper inteface class to allow posing tasks to be
 * invoked on UI thread.
 */
class IUIThreadDispatcher {
public:
    virtual void RunOnUIThread(std::function<void()> task) = 0;
    virtual ~IUIThreadDispatcher() = default;
};