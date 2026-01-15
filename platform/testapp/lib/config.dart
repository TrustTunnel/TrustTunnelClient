import 'package:toml/toml.dart';

class VpnConfig {
  /// The map to encode as a TOML document.
  static const String defaultConfig = """
# Logging level [info, debug, trace]
loglevel = "info"

# VPN mode.
# Defines client connections routing policy:
# * general: route through a VPN endpoint all connections except ones which destinations are in exclusions,
# * selective: route through a VPN endpoint only the connections which destinations are in exclusions.
vpn_mode = "general"

# When disabled, all connection requests are routed directly to target hosts
# in case connection to VPN endpoint is lost. This helps not to break an
# Internet connection if user has poor connectivity to an endpoint.
# When enabled, incoming connection requests which should be routed through
# an endpoint will not be routed directly in that case.
killswitch_enabled = true

# When enabled, a post-quantum group may be used for key exchange
# in TLS handshakes initiated by the VPN client.
post_quantum_group_enabled = true

# Domains and addresses which should be routed in a special manner.
# Supported syntax:
#   * domain name
#     * if starts with "*.", any subdomain of the domain will be matched including
#       www-subdomain, but not the domain itself (e.g., `*.example.com` will match
#       `sub.example.com`, `sub.sub.example.com`, `www.example.com`, but not `example.com`)
#     * if starts with "www." or it's just a domain name, the domain itself and its
#       www-subdomain will be matched (e.g. `example.com` and `www.example.com` will
#       match `example.com` `www.example.com`, but not `sub.example.com`)
#   * ip address
#     * recognized formats are:
#       * [IPv6Address]:port
#       * [IPv6Address]
#       * IPv6Address
#       * IPv4Address:port
#       * IPv4Address
#     * if port is not specified, any port will be matched
#   * CIDR range
#     * recognized formats are:
#       * IPv4Address/mask
#       * IPv6Address/mask
exclusions = []

# DNS upstreams.
# If specified, the library intercepts and routes plain DNS queries
# going through the endpoint to the DNS resolvers.
# One of the following kinds:
#   * 8.8.8.8:53 -- plain DNS
#   * tcp://8.8.8.8:53 -- plain DNS over TCP
#   * tls://1.1.1.1 -- DNS-over-TLS
#   * https://dns.adguard.com/dns-query -- DNS-over-HTTPS
#   * sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
#   * quic://dns.adguard.com:8853 -- DNS-over-QUIC
dns_upstreams = []

# The set of endpoint connection settings
[endpoint]
# Endpoint host name, used for TLS session establishment
hostname = "testhostname.com"
# Endpoint addresses.
# The exact address is selected by the pinger. Absence of IPv6 addresses in
# the list makes the VPN client reject IPv6 connections which must be routed
# through the endpoint with unreachable code.
addresses = ["1.2.3.4:443"]
# Username for authorization
username = "test"
# Password for authorization
password = "test"
# TLS client random prefix and mask (hex string, format: prefix[/mask])
client_random = ""
# Skip the endpoint certificate verification?
# That is, any certificate is accepted with this one set to true.
skip_verification = false
# Path to a file containing the endpoint certificate.
# If not specified, the endpoint certificate is verified using the system storage.
certificate = '''
-----BEGIN CERTIFICATE-----
MIIBYTCCAQagAwIBAgIJAO1RB+L1CAExMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMM
EHRlc3Rob3N0bmFtZS5jb20wHhcNMjUwNzE4MDAwMDAwWhcNMjYwNzE4MDAwMDAw
WjAbMRkwFwYDVQQDDBB0ZXN0aG9zdG5hbWUuY29tMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEVpl5VXvMLoO3gzXNC4AoDqkpUzWcloeZEFhQLrvVfv+iVVpiIsSx
k7cb1Lxsx6r8uvPTN/IPlzC5SrfdhH/L2KMzMDEwLwYDVR0RBCgwJoIQdGVzdGhv
c3RuYW1lLmNvbYISKi50ZXN0aG9zdG5hbWUuY29tMAoGCCqGSM49BAMCA0kAMEYC
IQCWPhW7uUqNNGuwp0OIQuvfYU/slTQyhncGyoZMqA5weQIhAMQ3pbufh97ujgH7
IID3ebZflKrRWfh/NHq3u+AFoadv
-----END CERTIFICATE-----
'''
# Protocol to be used to communicate with the endpoint [http2, http3]
upstream_protocol = "http2"
# Fallback protocol to be used in case the main one fails [<none>, http2, http3]
upstream_fallback_protocol = ""
# Is anti-DPI measures should be enabled
anti_dpi = false


# Defines the way to listen to network traffic by the kind of the nested table.
# Possible types:
#   * socks: SOCKS5 proxy with UDP support,
#   * tun: TUN device.
[listener]

[listener.tun]
# Name of the interface used for connections made by the VPN client.
# On Linux and Windows, it is detected automatically if not specified.
# On macOS, it defaults to `en0` if not specified.
# On Windows, an interface index as shown by `route print`, written as a string, may be used instead of a name.
bound_if = ""
# Routes in CIDR notation to set to the virtual interface
included_routes = ["0.0.0.0/0", "2000::/3"]
# Routes in CIDR notation to exclude from routing through the virtual interface
excluded_routes = ["0.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"]
# MTU size on the interface
mtu_size = 1500

# [listener.socks]
# # IP address to bind the listener to
# address = "127.0.0.1:1080"
# # Username for authentication if desired
# username = ""
# # Password for authentication if desired
# password = ""
""";
}