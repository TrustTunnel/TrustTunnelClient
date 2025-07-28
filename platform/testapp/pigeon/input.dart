import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(PigeonOptions(
  dartOut: 'lib/native_communication.dart',
  dartOptions: DartOptions(),
  kotlinOut:
  'android/app/src/main/kotlin/com/adguard/testapp/NativeCommunication.kt',
  kotlinOptions: KotlinOptions(),
  dartPackageName: 'com_adguard_testapp',
))

@HostApi()
abstract class NativeVpnInterface {
  void start(String config);

  void stop();
}

@FlutterApi()
abstract class FlutterCallbacks {
  void onStateChanged(int state);
}