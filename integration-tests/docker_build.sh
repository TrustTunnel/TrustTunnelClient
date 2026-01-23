#!/usr/bin/env bash

set -e

# Docker build orchestration script for integrated tests
# Usage: ./docker_build.sh [client|endpoint|image]

# Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_IMAGE="adguard/core-libs:2.8"

# Default Git URLs
VPN_LIBS_GIT_URL="${VPN_LIBS_GIT_URL:-https://github.com/TrustTunnel/TrustTunnelClient}"
VPN_ENDPOINT_GIT_URL="${VPN_ENDPOINT_GIT_URL:-https://github.com/TrustTunnel/TrustTunnel}"

# Default root directories
VPN_LIBS_ROOT="${VPN_LIBS_ROOT:-$SCRIPT_DIR/repos/vpn-libs}"
VPN_ENDPOINT_ROOT="${VPN_ENDPOINT_ROOT:-$SCRIPT_DIR/repos/vpn-libs-endpoint}"

# Default volumes
OUTPUT_VOLUME="$SCRIPT_DIR/output"

# Function to show usage
usage() {
    echo "Usage: $0 [client|endpoint|image]"
    echo ""
    echo "Parameters:"
    echo "  client    - Build VPN client"
    echo "  endpoint  - Build VPN endpoint"
    echo "  image     - Build Docker image for testing"
    echo ""
    echo "Environment variables:"
    echo "  VPN_LIBS_ROOT      - VPN libs source directory (default: $VPN_LIBS_ROOT)"
    echo "  VPN_ENDPOINT_ROOT  - VPN endpoint source directory (default: $VPN_ENDPOINT_ROOT)"
    echo "  OUTPUT_VOLUME      - Output directory to mount (default: $OUTPUT_VOLUME)"
    echo "  CONAN_REPO_URL     - Conan repository URL (for client builds)"
    echo "  VPN_LIBS_GIT_URL   - Git URL for VPN libs (default: $VPN_LIBS_GIT_URL)"
    echo "  VPN_ENDPOINT_GIT_URL - Git URL for VPN endpoint (default: $VPN_ENDPOINT_GIT_URL)"
    exit 1
}

# Function to ensure repository is checked out
ensure_repository() {
    local repo_dir="$1"
    local git_url="$2"
    local repo_name="$3"

    if [ ! -d "$repo_dir" ]; then
        echo "$repo_name directory not found at $repo_dir"
        echo "Cloning from $git_url..."

        # Create parent directory if it doesn't exist
        mkdir -p "$(dirname "$repo_dir")"

        # Clone the repository
        git clone "$git_url" "$repo_dir"

        if [ $? -ne 0 ]; then
            echo "Error: Failed to clone $repo_name from $git_url"
            exit 1
        fi

        echo "Successfully cloned $repo_name"
    else
        echo "$repo_name directory found at $repo_dir"
    fi
}

# Function to build client
build_client() {
    echo "Building VPN client..."

    # Ensure VPN libs repository is available
    ensure_repository "$VPN_LIBS_ROOT" "$VPN_LIBS_GIT_URL" "VPN libs"

    # Ensure output directory exists
    mkdir -p "$OUTPUT_VOLUME"

    # Set up environment variables for the container
    ENV_ARGS=""
    if [ -n "$CONAN_REPO_URL" ]; then
        ENV_ARGS="$ENV_ARGS -e CONAN_REPO_URL=$CONAN_REPO_URL"
    fi

    # Run the build
    docker run --rm \
        --volume "$VPN_LIBS_ROOT:/source/vpn-libs" \
        --volume "$SCRIPT_DIR:/source/integration-tests:ro" \
        --volume "$OUTPUT_VOLUME:/output" \
        $ENV_ARGS \
        "$DOCKER_IMAGE" \
        /source/integration-tests/build_client.sh

    echo "Client build completed. Output available in: $OUTPUT_VOLUME"
}

# Function to build endpoint
build_endpoint() {
    echo "Building VPN endpoint..."

    # Ensure VPN endpoint repository is available
    ensure_repository "$VPN_ENDPOINT_ROOT" "$VPN_ENDPOINT_GIT_URL" "VPN endpoint"

    # Ensure output directory exists
    mkdir -p "$OUTPUT_VOLUME"

    # Run the build
    docker run --rm \
        --volume "$VPN_ENDPOINT_ROOT:/source/vpn-libs-endpoint" \
        --volume "$SCRIPT_DIR:/source/integration-tests:ro" \
        --volume "$OUTPUT_VOLUME:/output" \
        "$DOCKER_IMAGE" \
        /source/integration-tests/build_endpoint.sh

    echo "Endpoint build completed. Output available in: $OUTPUT_VOLUME"
}

# Function to build Docker image
build_image() {
    echo "Building Docker image..."

    # Build the Docker image
    docker build -t core-libs-testing image

    if [ $? -eq 0 ]; then
        echo "Docker image 'core-libs-testing' built successfully!"
    else
        echo "Error: Failed to build Docker image"
        exit 1
    fi
}

# Main script logic
if [ $# -eq 0 ]; then
    echo "Error: No build target specified."
    usage
fi

case "$1" in
    client)
        build_client
        ;;
    endpoint)
        build_endpoint
        ;;
    image)
        build_image
        ;;
    *)
        echo "Error: Unknown build target '$1'"
        usage
        ;;
esac

echo "Build process completed successfully!"
