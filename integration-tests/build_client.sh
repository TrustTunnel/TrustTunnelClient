#!/usr/bin/env bash

set -e -x

# Build script for VPN client in integrated tests
# This script builds the trusttunnel client and copies output to the output volume

# Variables
SOURCE_DIR="${SOURCE_DIR:-/source}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"

# Make modifyable source directory

VPN_LIBS_DIR="${SOURCE_DIR}/vpn-libs"
BUILD_DIR="${BUILD_DIR:-/build}"

echo "Starting client build process..."

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Check if CONAN_REPO_URL is set (required for client builds)
if [ -z "$CONAN_REPO_URL" ]; then
    echo "Error: CONAN_REPO_URL environment variable is required for client builds"
    echo "Please set CONAN_REPO_URL to your Conan repository URL"
    exit 1
fi

# Set up Conan repository
echo "Setting up Conan repository: $CONAN_REPO_URL"
conan remote add --index 0 art "$CONAN_REPO_URL"

echo "Building trusttunnel_client..."
# The build goes through the clang-relwithdebinfo CMake preset, into the
# out-of-tree BUILD_DIR this container mounts.
make -C "${VPN_LIBS_DIR}" \
    PRESET=clang-relwithdebinfo \
    BUILD_DIR="$BUILD_DIR" \
    SKIP_BOOTSTRAP=1 \
    build_trusttunnel_client

echo "Copying built client to output directory..."
cp "$BUILD_DIR/trusttunnel/trusttunnel_client" "$OUTPUT_DIR/"

# Copy any additional test scripts if they exist
if [ -d "$SOURCE_DIR/integrated-tests/client" ]; then
    echo "Copying client test scripts..."
    # The directory may be empty: without nullglob the glob stays literal and
    # cp fails on a missing file, so expand it explicitly instead of hiding the
    # failure with '|| true'.
    shopt -s nullglob
    client_scripts=("$SOURCE_DIR"/integrated-tests/client/*)
    shopt -u nullglob
    if [ ${#client_scripts[@]} -gt 0 ]; then
        cp -r "${client_scripts[@]}" "$OUTPUT_DIR/"
    else
        echo "No client test scripts to copy"
    fi
fi

echo "Client build completed successfully!"
echo "Output files:"
ls -la "$OUTPUT_DIR"
