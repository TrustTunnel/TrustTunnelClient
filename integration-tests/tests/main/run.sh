#!/usr/bin/env bash

set -e -x

# Main test runner script
# This script sets up the endpoint, runs it in the background, executes tests, and cleans up
# Usage: run.sh [protocol] [mode] [socks_port] [log_file_name]

# Test parameters (with defaults)
PROTOCOL="${1:-http2}"
MODE="${2:-tun}"
SOCKS_PORT="${3:-7777}"
LOG_FILE_NAME="${4:-vpn_${MODE}_${PROTOCOL}.log}"

# Variables
TEST_DIR="${TEST_DIR:-/tests}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
LOG_FILE="vpn_endpoint.log"
ENDPOINT_HOSTNAME="${ENDPOINT_HOSTNAME:-endpoint.test}"
ENDPOINT_PID_FILE="${OUTPUT_DIR}/vpn_endpoint.pid"
CLIENT_PID_FILE="${OUTPUT_DIR}/vpn_client.pid"
CLIENT_DIR="${CLIENT_DIR:-/output}"

# These will be determined after endpoint starts
ENDPOINT_IP=""
ENDPOINT_IPV6=""

echo "Starting main test runner..."

# Cleanup function
cleanup() {
    echo "Cleaning up..."

    # Stop VPN client if running
    if [ -f "$CLIENT_PID_FILE" ]; then
        CLIENT_PID=$(cat "$CLIENT_PID_FILE" 2>/dev/null || echo "")
        if [ -n "$CLIENT_PID" ] && kill -0 "$CLIENT_PID" 2>/dev/null; then
            echo "Stopping VPN client (PID: $CLIENT_PID)..."
            kill "$CLIENT_PID" || true
            wait "$CLIENT_PID" 2>/dev/null || true
            echo "VPN client stopped."
        fi
        rm -f "$CLIENT_PID_FILE"
    fi

    # Stop VPN endpoint if running
    if [ -f "$ENDPOINT_PID_FILE" ]; then
        ENDPOINT_PID=$(cat "$ENDPOINT_PID_FILE" 2>/dev/null || echo "")
        if [ -n "$ENDPOINT_PID" ] && kill -0 "$ENDPOINT_PID" 2>/dev/null; then
            echo "Stopping VPN endpoint (PID: $ENDPOINT_PID)..."
            kill "$ENDPOINT_PID" || true
            wait "$ENDPOINT_PID" 2>/dev/null || true
            echo "VPN endpoint stopped."
        fi
        rm -f "$ENDPOINT_PID_FILE"
    fi

    # Clean up network namespace if it exists
    if ip netns list | grep -q "^tun"; then
        echo "Removing network namespace 'tun'..."
        ip netns delete tun || true
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

echo "Step 1: Setting up endpoint..."
# Run endpoint setup
OUTPUT_DIR="$OUTPUT_DIR" "$TEST_DIR/endpoint_setup.sh"

echo "Step 2: Starting VPN endpoint..."
# Start the endpoint in the background
"$TEST_DIR/endpoint_run.sh" "$LOG_FILE"

echo "Step 3: Determining endpoint IP addresses..."
# Get the endpoint IP addresses (since it's running locally, use localhost)
ENDPOINT_IP="$(ip addr show eth0 | sed -nE 's|.*inet (.*)/.*global.*|\1|p')"
ENDPOINT_IPV6="$(ip addr show eth0 | sed -nE 's|.*inet6 (.*)/.*global.*|\1|p')"
ENDPOINT_PORT="4433"

echo "Endpoint addresses: IPv4=$ENDPOINT_IP, IPv6=$ENDPOINT_IPV6"

echo "Step 4: Setting up client..."

# Run client setup with endpoint port 4433 for local endpoint
if [[ "$MODE" == "socks" ]]; then
    "$TEST_DIR/client_setup.sh" "$ENDPOINT_HOSTNAME" "$ENDPOINT_IP" "$ENDPOINT_IPV6" "$ENDPOINT_PORT" "$PROTOCOL" "$MODE" "$LOG_FILE_NAME" "$SOCKS_PORT"
else
    "$TEST_DIR/client_setup.sh" "$ENDPOINT_HOSTNAME" "$ENDPOINT_IP" "$ENDPOINT_IPV6" "$ENDPOINT_PORT" "$PROTOCOL" "$MODE" "$LOG_FILE_NAME"
fi

echo "Step 5: Starting client..."
# Run the VPN client
"$TEST_DIR/client_run.sh" "$LOG_FILE_NAME"

echo "Step 6: Running tests..."
# Run the actual tests directly
if [[ "${LIVE_TESTS:-0}" == "1" ]]; then
    TUN_TEST_SCRIPT="$TEST_DIR/main/tun_tests.sh"
    SOCKS_TEST_SCRIPT="$TEST_DIR/main/socks_tests.sh"
    echo "Live mode enabled: using online test scripts"
else
    TUN_TEST_SCRIPT="$TEST_DIR/main/tun_tests_offline.sh"
    SOCKS_TEST_SCRIPT="$TEST_DIR/main/socks_tests_offline.sh"
    echo "Offline mode enabled: using offline test scripts"
fi

if [[ "$MODE" == "socks" ]]; then
    if [ -f "$SOCKS_TEST_SCRIPT" ]; then
        echo "Running SOCKS tests with endpoint IP: $ENDPOINT_IP, port: $SOCKS_PORT"
        "$SOCKS_TEST_SCRIPT" "$ENDPOINT_IP" "$SOCKS_PORT"
    else
        echo "Warning: SOCKS test script not found, skipping SOCKS tests"
    fi
else
    if [ -f "$TUN_TEST_SCRIPT" ]; then
        echo "Running TUN tests with endpoint IP: $ENDPOINT_IP"
        "$TUN_TEST_SCRIPT" "$ENDPOINT_IP"
    else
        echo "Warning: TUN test script not found, skipping TUN tests"
    fi
fi

echo "Step 7: Tests completed, cleanup will be handled by trap"
echo "Main test run completed successfully!"