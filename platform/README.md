# <p align="center">TrustTunnel CLI Client</p>

Here you can find the adapters for Android, Apple and Windows.

These adapters are designed to help integrate TrustTunnel Client Libraries into applications written in a native platform code.

For example, these adapters are used in a [Flutter-based TrustTunnel GUI client](https://github.com/TrustTunnel/TrustTunnelFlutterClient)

In a `testapp` directory you can find a simple Flutter application that demonstrates the adapters could be integrated.

## Endpoint TLS profile

Adapters pass the same TOML configuration as the CLI client, so the TLS ClientHello fingerprint of an endpoint is selected with `[endpoint].tls_profile` (string, `chrome` by default):

| Value | ClientHello to mimic |
| --- | --- |
| `chrome` | Current Chrome stable (default) |
| `chrome_canary` | Current Chrome Canary; usually the same as `chrome` |
| `safari` | Safari |
| `firefox` | Firefox |
| `okhttp` | OkHttp (Android) |
| `openssl` | OpenSSL defaults |
| `boringssl` | The ClientHello of the linked TLS library, no mimicry (`default` is a deprecated alias) |

The `chrome` and `chrome_canary` profiles track the current browser release, so their ClientHello changes between client releases and a fingerprint is only valid for the release that ships it. `boringssl` is meant for debugging: it does not impersonate a browser, so it stands out to fingerprinting middleboxes.

Adapters that surface this setting to users should use the values above verbatim and pass them through unchanged; an unknown value makes `build_config()` reject the whole configuration.
