#ifndef RUNNER_FLUTTER_WINDOW_H_
#define RUNNER_FLUTTER_WINDOW_H_

#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>

#include <memory>

#include "pigeon/native_communication.h"
#include "win32_window.h"
#include "ui_thread_dispatcher.h"

// A window that does nothing but host a Flutter view.
class FlutterWindow : public Win32Window, public IUIThreadDispatcher {
 public:
  // Creates a new FlutterWindow hosting a Flutter view running |project|.
  explicit FlutterWindow(const flutter::DartProject& project);
  virtual ~FlutterWindow();

  void RunOnUIThread(std::function<void()> task) override;

 protected:
  // Win32Window:
  bool OnCreate() override;
  void OnDestroy() override;
  LRESULT MessageHandler(HWND window, UINT const message, WPARAM const wparam,
                         LPARAM const lparam) noexcept override;

 private:
  // The project to run.
  flutter::DartProject project_;

  // The Flutter instance hosted by this window.
  std::unique_ptr<flutter::FlutterViewController> flutter_controller_;

  std::unique_ptr<NativeVpnInterface> native_interface_;
};

#endif  // RUNNER_FLUTTER_WINDOW_H_
