#!/usr/bin/env bash

set -e -x

# Endpoint setup script for VPN endpoint
# This script generates SSL certificates and creates configuration files

# Variables
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
ENDPOINT_HOSTNAME="${ENDPOINT_HOSTNAME:-endpoint.test}"
CONFIG_FILE="vpn.conf"
TLS_HOSTS_SETTINGS_FILE="tls_hosts.conf"
RULES_FILE="rules.conf"
TLS_CLIENT_RANDOM="${TLS_CLIENT_RANDOM:-160200085c112870/9622006c5f112b73}"
CREDENTIALS_FILE="credentials.conf"
USERNAME="premium"
PASSWORD="premium"

echo "Starting endpoint setup process..."

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Install OpenSSL if not available
if ! command -v openssl &> /dev/null; then
    echo "Installing OpenSSL..."
    apt update && apt install -y openssl
fi

echo "Generating SSL certificates..."
cd "$OUTPUT_DIR"
openssl req -new -x509 -sha256 -newkey rsa:2048 -nodes -days 1000 \
    -keyout key.pem -out cert.pem \
    -subj "/C=de/CN=$ENDPOINT_HOSTNAME" \
    -addext "subjectAltName = DNS:$ENDPOINT_HOSTNAME, DNS:*.$ENDPOINT_HOSTNAME"

echo "Creating VPN configuration file..."
cat > "$CONFIG_FILE" << EOF
listen_address = "[::]:4433"
allow_private_network_connections = true
credentials_file = "$CREDENTIALS_FILE"
rules_file = "$RULES_FILE"
[listen_protocols.http1]
[listen_protocols.http2]
[listen_protocols.quic]
[icmp]
interface_name = "eth0"
EOF

echo "Creating TLS hosts settings file..."
cat > "$TLS_HOSTS_SETTINGS_FILE" << EOF
[[main_hosts]]
hostname = "$ENDPOINT_HOSTNAME"
cert_chain_path = "cert.pem"
private_key_path = "key.pem"
EOF

echo "Creating connection rules file..."
cat > "$RULES_FILE" << EOF
[[rule]]
tls_client_random = "$TLS_CLIENT_RANDOM"
action = "allow"
[[rule]]
action = "deny"
EOF

echo "Creating credentials file..."
cat > "$CREDENTIALS_FILE" << EOF
[[client]]
username = "$USERNAME"
password = "$PASSWORD"
EOF

echo "Endpoint setup completed successfully!"
echo "Generated files:"
ls -la "$OUTPUT_DIR"
