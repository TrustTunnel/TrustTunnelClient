import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)
    guard let controller = window?.rootViewController as? FlutterViewController else {
      fatalError("rootViewController is not type FlutterViewController")
    }
    // Setup communication between flutter and swift
    let callbacks = FlutterCallbacks(binaryMessenger: controller.binaryMessenger)
    NativeVpnInterfaceSetup.setUp(binaryMessenger: controller.binaryMessenger,
                                  api: NativeVpnInterfaceImpl(callbacks: callbacks));
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}
