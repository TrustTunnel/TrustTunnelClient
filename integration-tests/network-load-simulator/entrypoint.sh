#!/usr/bin/env bash

set -e -x

source config.conf

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
addresses = ["$ENDPOINT_IP:443"]
username = "$ENDPOINT_USERNAME"
password = "$ENDPOINT_PASSWORD"
skip_verification = true
upstream_protocol = "$PROTOCOL"
upstream_fallback_protocol = "$PROTOCOL"
anti_dpi = true
END
)

for ip in $(grep nameserver /etc/resolv.conf | awk '{print $2}'); do
  iptables -I OUTPUT -o eth0 -d "$ip" -j ACCEPT || true
done

iptables -I OUTPUT -o eth0 -d "$ENDPOINT_IP" -j ACCEPT
iptables -A OUTPUT -o eth0 -j DROP

set +e

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
  # Check that standalone_client executable exists
  if [ ! -f standalone_client ]; then
    echo "standalone_client executable not found!"
    exit 1
  fi

  ./standalone_client >>"/output/$LOG_FILE_NAME" 2>&1
  exit_status=$?

  if [ $exit_status -ne 0 ]; then
      echo "Error occurred while running standalone_client. Exit status: $exit_status"
      tail -n 50 "/output/$LOG_FILE_NAME"
  fi
else
  cat >>standalone_client.toml <<EOF
$COMMON_CONFIG

[listener.socks]
address = "127.0.0.1:$SOCKS_PORT"
EOF
  ./standalone_client >>"/output/$LOG_FILE_NAME" 2>&1
fi
