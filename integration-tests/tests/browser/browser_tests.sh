#!/usr/bin/env bash

set -e -x

OUTPUT_DIR="${OUTPUT_DIR:-/output}"

# Retry policy for operations that depend on external services.
RETRY_ATTEMPTS="${RETRY_ATTEMPTS:-3}"
RETRY_DELAY="${RETRY_DELAY:-10}"

# Services that report the egress IP; the first one that answers is used.
IP_ECHO_URLS="${IP_ECHO_URLS:-https://api.ipify.org https://icanhazip.com https://ifconfig.me/ip}"

tunexec() {
    ip netns exec tun "$@"
}

retry() {
    local attempt=1
    local rc=0
    while true; do
        "$@" && return 0
        rc=$?
        if [ "$attempt" -ge "$RETRY_ATTEMPTS" ]; then
            echo "Command failed after $RETRY_ATTEMPTS attempts (exit code: $rc): $*" >&2
            return "$rc"
        fi
        echo "Attempt $attempt/$RETRY_ATTEMPTS failed (exit code: $rc), retrying in ${RETRY_DELAY}s: $*" >&2
        sleep "$RETRY_DELAY"
        attempt=$((attempt + 1))
    done
}

# Egress IP as seen by the given service through the tunnel ("tun") or directly
# ("direct"); only a well-formed IPv4 answer counts.
get_egress_ip() {
    local mode="$1"
    local url="$2"
    local ip
    if [ "$mode" = "tun" ]; then
        ip="$(tunexec curl -sS -4 --connect-timeout 5 --max-time 15 "$url" 2>/dev/null || true)"
    else
        ip="$(curl -sS -4 --connect-timeout 5 --max-time 15 "$url" 2>/dev/null || true)"
    fi
    ip="$(printf '%s' "$ip" | tr -d '[:space:]')"
    if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        echo "$ip"
        return 0
    fi
    return 1
}

# The egress IP inside the netns must differ from the direct one (both from the same
# service). Tracing stays off here: the addresses must not reach the CI logs.
assert_tunnel_used() {
    local attempt=1 url direct_ip="" tunnel_ip="" result=0
    set +x
    while [ "$attempt" -le "$RETRY_ATTEMPTS" ]; do
        for url in $IP_ECHO_URLS; do
            tunnel_ip="$(get_egress_ip tun "$url")" || tunnel_ip=""
            direct_ip="$(get_egress_ip direct "$url")" || direct_ip=""
            if [ -n "$tunnel_ip" ] && [ -n "$direct_ip" ]; then
                break 2
            fi
        done
        attempt=$((attempt + 1))
        sleep "$RETRY_DELAY"
    done

    if [ -z "$tunnel_ip" ] || [ -z "$direct_ip" ]; then
        echo "Error: no service answered on both paths, the leak check cannot be verified" >&2
        result=1
    elif [ "$direct_ip" = "$tunnel_ip" ]; then
        echo "Error: traffic does not go through the tunnel (the egress IPs are identical)" >&2
        result=1
    else
        echo "Tunnel is used: egress IPs differ (via $url)"
    fi
    set -x
    return "$result"
}

# Insert the outage rules at the top of the chains: the client setup adds its
# ACCEPT rules with -I, so appended DROP rules would never match.
disruption_rules_active=0

apply_disruption() {
    # Mark active first: if the second insert fails, the trap must still remove the first.
    disruption_rules_active=1
    iptables -I OUTPUT 1 -j DROP
    iptables -I INPUT 1 -j DROP
}

clear_disruption() {
    if [ "$disruption_rules_active" -eq 1 ]; then
        iptables -D OUTPUT -j DROP || true
        iptables -D INPUT -j DROP || true
        disruption_rules_active=0
    fi
}

# Never leave the container blackholed when the script fails mid-outage.
trap clear_disruption EXIT

# Browser test implementation
# This script runs the actual browser tests and should be executed inside the TUN network namespace
# Usage: browser_tests.sh

echo "Starting browser tests..."

# Use the local browser test files in the same directory
TEST_DIR="$(dirname "$0")"
cd "$TEST_DIR"

echo "Installing Node.js dependencies..."
retry env PUPPETEER_SKIP_DOWNLOAD=true yarn install

# Check that VPN client is running
echo "Checking if VPN client is running..."
sleep 5
if ! pgrep trusttunnel > /dev/null; then
    echo "VPN client is not running"
    exit 1
fi

echo "Testing that vpn-client actually works"
# Bounded: a hung request must not keep the job alive until the CI timeout.
tunexec curl -sS -I --connect-timeout 5 --max-time 15 https://google.com -4 >/dev/null
tunexec curl -sS -I --connect-timeout 5 --max-time 15 https://google.com -6 >/dev/null
assert_tunnel_used

echo "Running browser tests (steady state, 30 minutes)..."
STEADY_STATE_RESULT=0
# Drop any report left by a previous run: a crashed phase must not be mistaken for a fresh one.
rm -f output.json

# Run tests for 30 minutes
tunexec env TIME_LIMIT=30m VERBOSE=true node index.js || STEADY_STATE_RESULT=$?
cp output.json "${OUTPUT_DIR}/output1part.json" 2>/dev/null || true

echo "Simulating network problems..."
# Cut the network for a moment: the client should reconnect afterwards.
apply_disruption
sleep 1

# Send SIGHUP to client to trigger reconnection
PIDS=$(pgrep trusttunnel)
echo "PIDS: $PIDS"
for pid in $PIDS; do
    kill -SIGHUP $pid || true
done
sleep 9

# Restore network connectivity and wait for the tunnel to pass traffic again.
# The leak check below is fail-closed and retries on its own, so a tunnel that
# has not recovered yet is reported as a failure rather than ignored.
clear_disruption
sleep 60
assert_tunnel_used

echo "Running browser tests again after network recovery..."
RECOVERY_RESULT=0
rm -f output.json
tunexec env TIME_LIMIT=30m VERBOSE=true node index.js || RECOVERY_RESULT=$?

# The second phase must produce a fresh report: the previous one was removed above.
if [ -f output.json ]; then
    cp output.json "${OUTPUT_DIR}/output2part.json" 2>/dev/null || true
else
    echo "Warning: the second phase did not write output.json" >&2
fi

echo "Phase results: steady-state=$STEADY_STATE_RESULT, after-disruption=$RECOVERY_RESULT"
RESULT=0
if [ "$STEADY_STATE_RESULT" -ne 0 ] || [ "$RECOVERY_RESULT" -ne 0 ]; then
    RESULT=1
fi
echo "Browser tests completed with result: $RESULT"
exit "$RESULT"
