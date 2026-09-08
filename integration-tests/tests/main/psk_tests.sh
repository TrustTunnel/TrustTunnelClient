#!/usr/bin/env bash

set -e -x

# Negative PSK authentication check (tun mode, PSK scenario only):
# restart the client with a key that differs from the rule and make sure
# the tunnel never comes up.

ENDPOINT_IP="$1"
CLIENT_RANDOM_PSK_KEY="${CLIENT_RANDOM_PSK_KEY:-}"
TEST_DIR="${TEST_DIR:-/tests}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
CLIENT_PID_FILE="${OUTPUT_DIR}/vpn_client.pid"

tunexec() {
  ip netns exec tun "$@"
}

ip netns list | grep -q "^tun" || {
  echo "Error: tun netns not found"
  exit 1
}

cd "$OUTPUT_DIR"

# Stop the authenticated client
if [ -f "$CLIENT_PID_FILE" ]; then
    CLIENT_PID=$(cat "$CLIENT_PID_FILE")
    kill "$CLIENT_PID" 2>/dev/null || true
    while kill -0 "$CLIENT_PID" 2>/dev/null; do
        sleep 0.2
    done
    rm -f "$CLIENT_PID_FILE"
fi
sleep 1

# Swap in a key other than the one the endpoint rule uses
WRONG_KEY="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
if [ "$CLIENT_RANDOM_PSK_KEY" = "$WRONG_KEY" ]; then
    WRONG_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
fi
sed -i "s/^client_random_psk_key = .*/client_random_psk_key = \"$WRONG_KEY\"/" trusttunnel_client.toml

"$TEST_DIR/client_run.sh" "vpn_psk_negative.log"

for _ in $(seq 1 20); do
    if tunexec ip route show default | grep -q default; then
        echo "FAIL: tunnel came up with a non-matching client_random_psk_key"
        exit 1
    fi
    sleep 1
done
echo "...passed (tunnel stays down with a non-matching key)"
