#!/usr/bin/env bash

set -e -x

# Client setup script for VPN client
# This script configures iptables, creates client configuration, and runs the trusttunnel client
# Parameters: ENDPOINT_HOSTNAME ENDPOINT_IP ENDPOINT_IPV6 ENDPOINT_PORT PROTOCOL MODE LOG_FILE_NAME [SOCKS_PORT] [USERNAME] [PASSWORD]

ENDPOINT_HOSTNAME="$1"
ENDPOINT_IP="$2"
ENDPOINT_IPV6="$3"
ENDPOINT_PORT="$4"
PROTOCOL="$5"
MODE="$6"
LOG_FILE_NAME="$7"
SOCKS_PORT="$8"
# Optional parameters for browser tests
USERNAME="${9:-premium}"
PASSWORD="${10:-premium}"

OUTPUT_DIR="${OUTPUT_DIR:-/output}"
CLIENT_RANDOM="${CLIENT_RANDOM:-160200085c112870/9622006c5f112b73}"

# Change to output directory where the executable and config files are located
cd "$OUTPUT_DIR"

# Build endpoint addresses
if [[ -n "$ENDPOINT_IPV6" ]]; then
    ENDPOINT_ADDRESSES="[\"$ENDPOINT_IP:$ENDPOINT_PORT\", \"[$ENDPOINT_IPV6]:$ENDPOINT_PORT\"]"
else
    ENDPOINT_ADDRESSES="[\"$ENDPOINT_IP:$ENDPOINT_PORT\"]"
fi

echo "Starting client setup..."
echo "Endpoint: $ENDPOINT_HOSTNAME ($ENDPOINT_IP)"
echo "Protocol: $PROTOCOL, Mode: $MODE"
if [[ "$MODE" == "socks" ]]; then
  echo "SOCKS Port: $SOCKS_PORT"
fi
echo "Log file: $LOG_FILE_NAME"

# Create common configuration
COMMON_CONFIG=$(
  cat <<-END
loglevel = "trace"
vpn_mode = "general"
killswitch_enabled = true
exclusions = [
  "httpbin.agrd.dev",
  "cloudflare-dns.com",
]

[endpoint]
hostname = "$ENDPOINT_HOSTNAME"
addresses = $ENDPOINT_ADDRESSES
username = "$USERNAME"
password = "$PASSWORD"
skip_verification = true
upstream_protocol = "$PROTOCOL"
client_random = "$CLIENT_RANDOM"
END
)

echo "Setting up iptables rules..."

mkdir -p /sys/fs/cgroup/client
mkdir -p /sys/fs/cgroup/endpoint

# Allow DNS servers
for ip in $(grep nameserver /etc/resolv.conf | awk '{print $2}'); do
  iptables -I OUTPUT -m cgroup --path /client -o eth0 -d "$ip" -j ACCEPT || true
  ip6tables -I OUTPUT -m cgroup --path /client -o eth0 -d "$ip" -j ACCEPT || true
done

# Allow test exclusions
iptables -I OUTPUT -m cgroup --path /client -o eth0 -d "1.1.1.1" -j ACCEPT
iptables -I OUTPUT -m cgroup --path /client -o eth0 -d "httpbin.agrd.dev" -j ACCEPT -m comment --comment "httpbin.agrd.dev"
# Count test exclusions for endpoint too
iptables -I OUTPUT -m cgroup --path /endpoint -o eth0 -d "1.1.1.1" -j ACCEPT
iptables -I OUTPUT -m cgroup --path /endpoint -o eth0 -d "httpbin.agrd.dev" -j ACCEPT -m comment --comment "httpbin.agrd.dev"

# Allow endpoint communication
iptables -I OUTPUT -m cgroup --path /client -o eth0 -d "$ENDPOINT_IP" -j ACCEPT
iptables -A OUTPUT -m cgroup --path /client -o eth0 -j DROP

if [ -n "$ENDPOINT_IPV6" ]; then
  ip6tables -I OUTPUT -m cgroup --path /client -o eth0 -d "$ENDPOINT_IPV6" -j ACCEPT
  ip6tables -A OUTPUT -m cgroup --path /client -o eth0 -j DROP
fi

# Create network namespace for TUN mode (if it doesn't exist)
if ! ip netns list | grep -q "^tun"; then
    echo "Creating network namespace 'tun'..."
    ip netns add tun
    # localhost is required by Chrome
    ip netns exec tun ip link set lo up
else
    echo "Network namespace 'tun' already exists, reusing it."
fi

echo "Creating client configuration..."

# Create mode-specific configuration
if [[ "$MODE" == "tun" ]]; then
  cat >trusttunnel_client.toml <<EOF
$COMMON_CONFIG

[listener.tun]
bound_if = "eth0"
netns = "tun"
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
mtu_size = 1280
EOF
  echo "TUN mode configuration created"
else
  cat >trusttunnel_client.toml <<EOF
$COMMON_CONFIG

[listener.socks]
address = "127.0.0.1:$SOCKS_PORT"
EOF
  echo "SOCKS mode configuration created"
fi

echo "Client setup completed! Configuration ready for execution."
