<!-- markdownlint-disable MD041 -->
<p align="center">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_dark.svg" width="300px" alt="TrustTunnel" />
<img src="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_light.svg" width="300px" alt="TrustTunnel" />
</picture>
</p>

<p align="center">Free, fast, open-source and secure client for the TrustTunnel VPN</p>

<p align="center"><a href="https://github.com/TrustTunnel/TrustTunnel">Endpoint</a>
  · <a href="https://github.com/TrustTunnel/TrustTunnelFlutterClient">Flutter-based app</a>
  · <a href="https://agrd.io/ios_trusttunnel">App store</a>
  · <a href="https://agrd.io/android_trusttunnel">Play store</a>
</p>

TrustTunnel Client Libraries are a collection of C++ libraries that provide
client network traffic tunneling through a TrustTunnel endpoint. It supports
Linux, macOS, and Windows platforms.

If you are looking for a TrustTunnel CLI Client, please refer to the
[Getting Started](#getting-started).

---

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

- Some amazing feature.

- **TrustTunnel VPN Protocol**: The library implements the TrustTunnel VPN
  protocol, which is compatible with HTTP/1.1, HTTP/2, and QUIC. By mimicking
  regular network traffic, it becomes more difficult for government regulators to
  detect and block.

- **Traffic Tunneling**: The library is capable of tunneling TCP, UDP, and ICMP
  traffic from the client to the endpoint and back.

- **Cross-Platform Support**: It supports Linux, macOS, and Windows platforms,
  consistent experience across different operating systems.

- **System-Wide Tunnel and SOCKS5 Proxy**: It can be set up as a system-wide
  tunnel, utilizing a virtual network interface, as well as a SOCKS5 proxy.

- **Split Tunneling**: The library supports split tunneling, allowing users to
  exclude connections to certain domains or hosts from routing through the VPN
  endpoint, or vice versa, only routing connections to specific domains or
  hosts through the endpoint based on an exclusion list.

- **Custom DNS Upstream**: Users can specify a custom DNS upstream, which is
  used for DNS queries routed through the VPN endpoint.

---

## Getting Started

If you haven't yet set up the endpoint, refer to the
[Endpoint setup][endpoint-setup] documentation.

Once you have obtained the exported endpoint configuration for the client, refer
to the [Client setup][client-setup] documentation.

[endpoint-setup]: https://github.com/TrustTunnel/TrustTunnel/blob/master/README.md#endpoint-setup
[client-setup]: https://github.com/TrustTunnel/TrustTunnel/blob/master/README.md#client-setup

---

## Roadmap

While the library currently does not support peer-to-peer communication between clients, we have
plans to add this feature in future releases. Stay tuned for updates.

---

## License

Apache 2.0

---

## See also

- [TrustTunnel CLI Client reference](trusttunnel/README.md)
- [Development documentation](DEVELOPMENT.md)
- [Platform adapters](platform/README.md)
- [Android adapter](platform/android/README.md)
- [Apple adapter](platform/apple/README.md)
- [Windows adapter](platform/windows/README.md)
- [Changelog](CHANGELOG.md)
- [Verifying releases](VERIFY_RELEASES.md)
- [License](LICENSE)
