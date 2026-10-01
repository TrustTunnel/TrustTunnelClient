#!/usr/bin/env bash

set -e -x

OUTPUT_DIR="${OUTPUT_DIR:-/output}"

tunexec() {
    ip netns exec tun "$@"
}

# Insert the outage rules at the top of the chains: the client setup inserts its
# ACCEPT rules with -I, so an appended OUTPUT DROP is evaluated after the ACCEPT
# for the endpoint address and would not cut the tunnel.
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
PUPPETEER_SKIP_DOWNLOAD=true yarn install

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

# Restore network connectivity and wait for the tunnel to recover.
clear_disruption
sleep 60

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
