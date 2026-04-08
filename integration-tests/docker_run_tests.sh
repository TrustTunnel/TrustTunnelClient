#!/usr/bin/env bash

set -e

# Docker test runner script for integrated tests
# Usage: ./docker_run_tests.sh [main|main-live|browser]

# Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
DOCKER_IMAGE="core-libs-testing"

# Function to show usage
usage() {
    echo "Usage: $0 [main|main-live|browser]"
    echo ""
    echo "Parameters:"
    echo "  main         - Run main tests in offline mode (default for PR)"
    echo "  main-live    - Run main tests with live internet checks"
    echo "  browser      - Run browser tests"
    echo ""
    echo "Environment variables:"
    echo "  ENDPOINT_HOSTNAME - Hostname for SSL certificate generation (default: endpoint.test)"
    echo "  LOG_LEVEL        - Log level for endpoint (default: info)"
    exit 1
}

# Function to run main tests
run_main_tests() {
    echo "Running main tests..."

    # Set up environment variables for the container
    ENV_ARGS=""
    if [ -n "$ENDPOINT_HOSTNAME" ]; then
        ENV_ARGS="$ENV_ARGS -e ENDPOINT_HOSTNAME=$ENDPOINT_HOSTNAME"
    fi
    if [ -n "$LOG_LEVEL" ]; then
        ENV_ARGS="$ENV_ARGS -e LOG_LEVEL=$LOG_LEVEL"
    fi
    if [ -n "$LIVE_TESTS" ]; then
        ENV_ARGS="$ENV_ARGS -e LIVE_TESTS=$LIVE_TESTS"
    fi

    # Run the tests
    docker run --platform linux/amd64 --rm \
        --cap-add=NET_ADMIN \
        --cap-add=SYS_MODULE \
        --cap-add=SYS_ADMIN \
        --device /dev/net/tun \
        --privileged \
        --volume "$SCRIPT_DIR/tests:/tests:ro" \
        --volume "$OUTPUT_DIR:/output:rw" \
        $ENV_ARGS \
        "$DOCKER_IMAGE" \
        /tests/main/run.sh "$@"

    echo "Main tests completed."
}

# Function to run browser tests
run_browser_tests() {
    echo "Running browser tests..."

    # Browser tests require BAMBOO_VPN_APP_ID and BAMBOO_VPN_TOKEN
    if [[ -z "$BAMBOO_VPN_APP_ID" ]] || [[ -z "$BAMBOO_VPN_TOKEN" ]]; then
        echo "Error: Browser tests require BAMBOO_VPN_APP_ID and BAMBOO_VPN_TOKEN environment variables"
        echo "Please set these variables before running browser tests"
        exit 1
    fi

    docker run --rm --privileged --platform linux/amd64 \
        -v "$SCRIPT_DIR/tests:/tests:ro" \
        -v "$SCRIPT_DIR/output:/output:rw" \
        -e AGVPN_HELPER_URL="${AGVPN_HELPER_URL:-}" \
        "$DOCKER_IMAGE" \
        /tests/browser/run.sh "$BAMBOO_VPN_APP_ID" "$BAMBOO_VPN_TOKEN"

    echo "Browser tests completed."
}

# Main script logic
if [ $# -eq 0 ]; then
    echo "Error: No test type specified."
    usage
fi

case "$1" in
    main)
        shift
        LIVE_TESTS=0
        run_main_tests "$@"
        ;;
    main-live)
        shift
        LIVE_TESTS=1
        run_main_tests "$@"
        ;;
    browser)
        run_browser_tests
        ;;
    *)
        echo "Error: Unknown test type '$1'"
        usage
        ;;
esac

echo "Test run completed successfully!"
