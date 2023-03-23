#!/usr/bin/env bash

set -e -x

ENDPOINT_HOSTNAME="$1"
ENDPOINT_IP="$2"
ENDPOINT_IPV6="$3"
PROTOCOL="$4"
MODE="$5"
if [[ "$MODE" == "socks" ]]; then
  SOCKS_PORT="$6"
fi

COMMON_CONFIG=$(
  cat <<-END
    "server_info": {
        "hostname": "$ENDPOINT_HOSTNAME",
        "addresses": ["$ENDPOINT_IP:4433", "[$ENDPOINT_IPV6]:4433"],
        "username": "premium",
        "password": "premium",
        "skip_cert_verify": true,
        "upstream_protocol": "$PROTOCOL",
        "upstream_fallback_protocol": "$PROTOCOL"
    },
    "listener_type": "$MODE",
    "killswitch_enabled": true,
    "vpn_mode": "general",
    "loglevel": "trace",
END
)

DNS_IP=$(grep nameserver /etc/resolv.conf | awk '{print $2}')

iptables -I OUTPUT -o eth0 -d "$ENDPOINT_IP" -j ACCEPT
iptables -I OUTPUT -o eth0 -d "$DNS_IP" -j ACCEPT
ip6tables -I OUTPUT -o eth0 -d "$ENDPOINT_IPV6" -j ACCEPT
iptables -A OUTPUT -o eth0 -j DROP

if [[ "$MODE" == "tun" ]]; then
  {
    echo "{"
    echo "$COMMON_CONFIG"
    echo "
    \"tun_info\": {
        \"excluded_routes\": [
            \"0.0.0.0/8\",
            \"10.0.0.0/8\",
            \"172.16.0.0/12\",
            \"192.168.0.0/16\",
            \"224.0.0.0/3\"
        ],
        \"included_routes\": [
            \"0.0.0.0/0\",
            \"2000::/3\"
        ],
        \"mtu_size\": 1500
    }"
    echo "}"
  } >>standalone_client.conf
  ./standalone_client >> /tmp/vpn.log 2>&1
else
    {
      echo "{"
      echo "$COMMON_CONFIG"
      echo "
    \"socks_info\": {
        \"socks_user\": \"\",
        \"socks_pass\": \"\",
        \"socks_host\": \"127.0.0.1\",
        \"socks_port\": \"$SOCKS_PORT\"
    }"
      echo "}"
    } >>"standalone_client.conf"
    ./standalone_client >> /tmp/vpn.log 2>&1
fi
