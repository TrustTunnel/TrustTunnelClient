#!/usr/bin/env bash

set -e -x

source config.conf

cp /etc/resolv.conf resolv.conf
echo "nameserver 101.101.101.101" > /etc/resolv.conf

CREDS_RESPONSE=""
for i in {1..6}; do
  set +e
  CREDS_RESPONSE=$(timeout 10s ~/go/bin/gocurl "${CREDS_API_URL}" -X POST \
                 -H "Content-Type: application/x-www-form-urlencoded" \
                 -d "app_id=${APP_ID}&token=${TOKEN}")
  set -e

  if [[ ! -z "$CREDS_RESPONSE" ]]; then
    break
  fi
  sleep 1
done
cp -f resolv.conf /etc/resolv.conf

USERNAME=$(echo ${CREDS_RESPONSE} | jq -r '.result.username')
CREDS=$(echo ${CREDS_RESPONSE} | jq -r '.result.credentials')

COMMON_CONFIG=$(
  cat <<-END
loglevel = "trace"
vpn_mode = "general"
killswitch_enabled = true
exclusions = [
  "example.org",
  "cloudflare-dns.com",
]
dns_upstreams = ["8.8.8.8:53"]

[endpoint]
hostname = "$ENDPOINT_HOSTNAME"
addresses = ["$ENDPOINT_IP:443"]
username = "$USERNAME"
password = "$CREDS"
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
