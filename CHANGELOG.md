# CHANGELOG

* [Feature] The library now accepts CIDR range in exclusion list.

## 0.92.28

* Removed `vpn_network_manager_update_tun_interface_dns()` as redundant.

## 0.92.23

* The library now accepts a list of DNS upstreams instead of a single one.
  * `dns_upsteam` field of `VpnListenerConfig` renamed to `dns_upsteams`.
  * `dns_upsteam` field removed from `VpnDnsUpstreamUnavailableEvent`.

## 0.92.11

* [Feature] `h3://` scheme is now allowed for DNS upstream.

## 0.91.88

* DNS queries are now routed according to VPN settings. I.e., queries with domains
  matching exclusions are routed directly to the target resolver in the general mode,
  but queries not matching exclusions are routed through the endpoint. To do it correctly
  the library needs to know the system (see `dns_manager_set_tunnel_interface_servers()`)
  and TUN interface DNS servers (see `vpn_network_manager_update_tun_interface_dns()`).
* The library now has one centralized point for setting the outbound network
  interface for I/O operations - `vpn_network_manager_set_outbound_interface()`.
  * [Windows] Use the method above instead of the removed `vpn_win_set_bound_if()`.

## 0.91.82

* [Fix] Introduced an error code indicating that no connection attempts left
  after initial connect() call `VPN_EC_INITIAL_CONNECT_FAILED`.

## 0.91.45

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
