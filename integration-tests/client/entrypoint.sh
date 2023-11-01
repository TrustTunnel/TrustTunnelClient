#!/usr/bin/env bash

set -e -x

ENDPOINT_HOSTNAME="$1"
ENDPOINT_IP="$2"
ENDPOINT_IPV6="$3"
PROTOCOL="$4"
MODE="$5"
LOG_FILE_NAME="$6"
if [[ "$MODE" == "socks" ]]; then
  SOCKS_PORT="$7"
fi

COMMON_CONFIG=$(
  cat <<-END
loglevel = "trace"
vpn_mode = "general"
killswitch_enabled = true
exclusions = [
  "example.org",
  "cloudflare-dns.com",
]

[endpoint]
hostname = "$ENDPOINT_HOSTNAME"
addresses = ["$ENDPOINT_IP:4433", "[$ENDPOINT_IPV6]:4433"]
username = "premium"
password = "premium"
skip_verification = true
upstream_protocol = "$PROTOCOL"
upstream_fallback_protocol = "$PROTOCOL"
END
)

for ip in $(grep nameserver /etc/resolv.conf | awk '{print $2}'); do
  iptables -I OUTPUT -o eth0 -d "$ip" -j ACCEPT || true
  ip6tables -I OUTPUT -o eth0 -d "$ip" -j ACCEPT || true
done

# for test exclusions
iptables -I OUTPUT -o eth0 -d "1.1.1.1" -j ACCEPT
iptables -I OUTPUT -o eth0 -d "example.org" -j ACCEPT

iptables -I OUTPUT -o eth0 -d "$ENDPOINT_IP" -j ACCEPT
iptables -A OUTPUT -o eth0 -j DROP

if [ -n "$ENDPOINT_IPV6" ]; then
  ip6tables -I OUTPUT -o eth0 -d "$ENDPOINT_IPV6" -j ACCEPT
  ip6tables -A OUTPUT -o eth0 -j DROP
fi

if [[ "$MODE" == "tun" ]]; then
  cat >>standalone_client.toml <<EOF
$COMMON_CONFIG

[listener.tun]
bound_if = "eth0"
included_routes = [
    "0.0.0.0/0",
    "2000::/3",
]
excluded_routes = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/3",
]
mtu_size = 1500
EOF
  ./standalone_client >>"/output/$LOG_FILE_NAME" 2>&1
else
  cat >>standalone_client.toml <<EOF
$COMMON_CONFIG

[listener.socks]
address = "127.0.0.1:$SOCKS_PORT"
EOF
  ./standalone_client >>"/output/$LOG_FILE_NAME" 2>&1
fi
