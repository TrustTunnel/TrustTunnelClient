import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)
      
    // Setup communication between flutter and swift
    let callbacks = FlutterCallbacks(binaryMessenger: flutterViewController.engine.binaryMessenger)
    NativeVpnInterfaceSetup.setUp(binaryMessenger: flutterViewController.engine.binaryMessenger,
                                  api: NativeVpnInterfaceImpl(callbacks: callbacks));

    super.awakeFromNib()
  }
}
