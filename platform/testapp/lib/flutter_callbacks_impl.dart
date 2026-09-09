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

class ConnectionInfoNotifier extends ChangeNotifier {
  final List<String> _records = [];
  List<String> get records => List.unmodifiable(_records);

  void addRecord(String json) {
    _records.add(json);
    notifyListeners();
  }
}

class FlutterCallbacksImpl extends FlutterCallbacks {
  final VpnStateNotifier _stateNotifier;
  final ConnectionInfoNotifier _infoNotifier;

  FlutterCallbacksImpl(this._stateNotifier, this._infoNotifier);

  @override
  void onStateChanged(int state) {
    if (state >= VpnState.values.length) {
      return;
    }
    _stateNotifier.onStateChanged(VpnState.values[state]);
  }

  @override
  void onConnectionInfo(String json) {
    _infoNotifier.addRecord(json);
  }
}