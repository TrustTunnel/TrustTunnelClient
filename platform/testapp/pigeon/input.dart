import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(PigeonOptions(
  dartOut: 'lib/native_communication.dart',
  dartOptions: DartOptions(),
  kotlinOut:
  'android/app/src/main/kotlin/com/adguard/testapp/NativeCommunication.kt',
  kotlinOptions: KotlinOptions(),
  swiftOut: 'swift_common/generated/NativeCommunication.swift',
  swiftOptions: SwiftOptions(),
  cppHeaderOut: 'windows/runner/pigeon/native_communication.h',
  cppSourceOut: 'windows/runner/pigeon/native_communication.cpp',
  cppOptions: CppOptions(),
  dartPackageName: 'com_adguard_testapp',
))

@HostApi()
abstract class NativeVpnInterface {
  void start(String config);

  void stop();

  /// Export log files from the VPN process(es).
  ///
  /// Returns a list of absolute paths to snapshot files in a temporary
  /// directory. The caller is responsible for cleaning up these files.
  List<String> exportLogs();

  /// Clear all log files from the VPN process(es).
  ///
  /// On Apple, the VPN must be stopped before calling this.
  void clearLogs();
}

@FlutterApi()
abstract class FlutterCallbacks {
  void onStateChanged(int state);
  void onConnectionInfo(String info);
}