# CHANGELOG

* [Changed] `Location unavailable` semantics:
  * It is now considered as a fatal error, i.e. the client goes in the disconnected state.
    It is up to application to refresh a location data and restart the client.
  * It is now raised only after the client receives the abandon command.
    It is up to application to detect infinite recovery loop in case there are some
    connectivity issues.
* [Changed] [Windows] `vpn_abandon_endpoint()` now takes an endpoint as a parameter

## 0.91.20

* [Changed] [Windows] Calling `vpn_win_set_bound_if()` now turns off the socket protection instead of
  detecting an active network interface by itself. It's up to the application to call the new method
  `vpn_win_detect_active_if()` and pass its result to `vpn_win_set_bound_if()` to activate the socket
  protection.

## 0.91.10

* [Feature] Added Wintun support. Dll downloaded from www.wintun.net is needed for standalone_client to run under Windows.

## 0.90.15

* [Feature] Route QUIC connections according to the VPN mode instead of always dropping or redirecting them

## 0.90.13

* [Fix] Fix leaks and memory bugs in `tls_serialize_cert_chain`, `tls_free_serialized_chain`. Add tests.

## 0.90.12

* [Fix] Change signature of some exported functions to be more consistent with the rest and simpler for C# bindings.

## 0.90.6

* [Fix] Fix version increment script.

## 0.90.4

* [Feature] VpnLibs is now open-source.
