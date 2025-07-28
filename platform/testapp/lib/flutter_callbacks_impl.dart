
import 'package:flutter/cupertino.dart';

import 'native_communication.dart';

enum VpnState {
  disconnected,
  connecting,
  connected,
  waitingRecovery,
  recovering,
  waitingForNetwork
}

class VpnStateNotifier extends ChangeNotifier {
  VpnState _state = VpnState.disconnected;
  VpnState get state => _state;

  void onStateChanged(VpnState state) {
    _state = state;
    notifyListeners();
  }
}

class FlutterCallbacksImpl extends FlutterCallbacks {
  final VpnStateNotifier _notifier;
  FlutterCallbacksImpl(this._notifier);

  @override
  void onStateChanged(int state) {
    if (state >= VpnState.values.length) {
      return;
    }
    _notifier.onStateChanged(VpnState.values[state]);
  }
}