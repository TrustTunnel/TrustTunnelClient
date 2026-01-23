# Integration Tests Build System

This directory contains the new build system for VPN client and endpoint integration tests, replacing the old integration-tests approach with a script-based Docker build process.

## Files

### Build Scripts

- `docker_build.sh` - Main orchestration script that handles Docker builds and image creation
- `docker_run_tests.sh` - Test runner script (parameters: main or browser)
- `build_client.sh` - Script to build the VPN client (runs inside Docker container)
- `build_endpoint.sh` - Script to build the VPN endpoint (runs inside Docker container)
- `endpoint_setup.sh` - Script to generate SSL certificates and configuration files for endpoint
- `endpoint_run.sh` - Script to run the VPN endpoint (saves PID to /output/vpn_endpoint.pid)

### Test Scripts

- `tests/client_setup.sh` - Script to configure the VPN client with iptables rules and create configuration (port as 4th parameter, supports custom credentials for browser tests)
- `tests/client_run.sh` - Script to run the VPN client (saves PID to /output/vpn_client.pid)
- `tests/main/run.sh` - Main test orchestrator (setup → run endpoint → client → test → cleanup with PID management)
- `tests/main/socks_tests.sh` - SOCKS mode integration tests
- `tests/main/tun_tests.sh` - TUN mode integration tests (runs in network namespace)
- `tests/browser/run.sh` - Browser test orchestrator (uses agvpn_helper, always TUN mode with network namespace)
- `tests/browser/browser_tests.sh` - Browser test implementation (Puppeteer-based with network disruption testing)
- `tests/browser/index.js` - Node.js Puppeteer browser test script
- `tests/browser/package.json` - Node.js dependencies for browser tests

## Usage

### Build Docker Image

```bash
# Build the Docker image for testing
./docker_build.sh image
```

### Build VPN Client

```bash
# CONAN_REPO_URL is required for client builds
CONAN_REPO_URL="https://your-conan-repo.com" ./docker_build.sh client
```

### Build VPN Endpoint

```bash
./docker_build.sh endpoint
```

## Automatic Repository Management

The build script automatically handles repository cloning:

- If `VPN_LIBS_ROOT` directory doesn't exist, it will be cloned from `VPN_LIBS_GIT_URL`
- If `VPN_ENDPOINT_ROOT` directory doesn't exist, it will be cloned from `VPN_ENDPOINT_GIT_URL`
- Default Git URLs point to the official AdguardTeam repositories
- You can override Git URLs using environment variables for custom forks

## Environment Variables

### For All Builds

- `VPN_LIBS_ROOT` - VPN libs source directory (default: ./vpn-libs)
- `VPN_ENDPOINT_ROOT` - VPN endpoint source directory (default: ./vpn-libs-endpoint)
- `OUTPUT_VOLUME` - Output directory for build artifacts (default: ./output)
- `VPN_LIBS_GIT_URL` - Git URL for VPN libs (default: https://github.com/TrustTunnel/TrustTunnelClient)
- `VPN_ENDPOINT_GIT_URL` - Git URL for VPN endpoint (default: https://github.com/TrustTunnel/TrustTunnel)

### For Client Builds

- `CONAN_REPO_URL` - Conan repository URL for dependencies (**required**)

### For Endpoint Setup (endpoint_setup.sh)

- `ENDPOINT_HOSTNAME` - Hostname for SSL certificate generation (default: endpoint.test)
- `OUTPUT_DIR` - Directory for setup files (default: /output)

### For Browser Tests

- `BAMBOO_VPN_APP_ID` - Required for browser tests - VPN app ID for backend authentication
- `BAMBOO_VPN_TOKEN` - Required for browser tests - VPN token for backend authentication
- `AGVPN_HELPER_URL` - Optional URL to download agvpn_helper if not present in output directory

## Examples

### Build Docker image

```bash
./docker_build.sh image
```

### Build client with custom Conan repository

```bash
CONAN_REPO_URL="https://your-conan-repo.com" ./docker_build.sh client
```

### Build endpoint (hostname is set during setup phase)

```bash
./docker_build.sh endpoint
```

### Build with custom output directory

```bash
OUTPUT_VOLUME="/tmp/build-output" ./docker_build.sh client
```

### Build with custom Git repositories

```bash
VPN_LIBS_GIT_URL="https://github.com/yourfork/TrustTunnelClient" ./docker_build.sh client
VPN_ENDPOINT_GIT_URL="https://github.com/yourfork/TrustTunnel" ./docker_build.sh endpoint
```

## Endpoint Workflow

For the endpoint, the build process is now separated into distinct phases:

1. **Build**: `./docker_build.sh endpoint` - Compiles the VPN endpoint binary
2. **Setup**: `./endpoint_setup.sh` - Generates SSL certificates and configuration files
3. **Run**: `./endpoint_run.sh` - Starts the VPN endpoint server

### Running endpoint setup and execution separately

```bash
# Build the endpoint
./docker_build.sh endpoint

# Setup certificates and config (can be run in Docker or directly)
OUTPUT_DIR="./output" ENDPOINT_HOSTNAME="my-endpoint.local" ./endpoint_setup.sh

# Run the endpoint (typically in Docker)
OUTPUT_DIR="./output" LOG_LEVEL="debug" ./endpoint_run.sh
```

## Running Tests

The test system provides automated test execution with endpoint management:

### Test Types

- **Main tests**: `./docker_run_tests.sh main`
- **Browser tests**: `./docker_run_tests.sh browser`

### Test Workflow

#### Main Tests

Each main test run automatically:

1. Sets up the VPN endpoint (certificates, configuration)
2. Starts the endpoint in the background (saves PID to `/output/vpn_endpoint.pid`)
3. Determines endpoint IP addresses
4. Sets up the VPN client (iptables, configuration)
   - For TUN mode: Creates network namespace 'tun' for isolation
5. Starts the VPN client (saves PID to `/output/vpn_client.pid`)
6. Runs the appropriate test script directly:
   - `socks_tests.sh` for SOCKS mode tests
   - `tun_tests.sh` for TUN mode tests (executed inside 'tun' netns)
7. Stops processes using PID files and cleans up (including network namespace)

#### Browser Tests

Each browser test run automatically:

1. Downloads `agvpn_helper` if not present (using `AGVPN_HELPER_URL` if provided)
2. Fetches real backend location and credentials using `agvpn_helper`
3. Sets up the VPN client with real backend configuration
4. Starts the VPN client in TUN mode (saves PID to `/output/vpn_client.pid`)
5. Creates network namespace 'tun' for isolation
6. Installs Node.js and browser test dependencies
7. Runs Puppeteer-based browser tests for 30 minutes
8. Simulates network disruption (drops traffic, sends SIGHUP to client)
9. Restores network and runs tests again for 30 minutes
10. Collects test results in `/output/output1part.json` and `/output/output2part.json`
11. Stops processes using PID files and cleans up

**Note**: The test container has access to built binaries (`trusttunnel_client`, `trusttunnel_endpoint`) via the mounted `/output` directory.

### Test Parameters

The test runners (`tests/main/run.sh` and `tests/browser/run.sh`) accept optional parameters:

- `protocol` - Protocol to test (default: https)
- `mode` - Test mode: tun or socks (default: tun)
- `socks_port` - SOCKS port when mode=socks (default: 7777)
- `log_file_name` - Log file name (default: vpn_{mode}_{protocol}.log)

These parameters are automatically passed to the underlying `run_tests.sh` scripts along with endpoint connection details.

### Examples

```bash
# Run main tests
./docker_run_tests.sh main

# Run browser tests (requires BAMBOO_VPN_APP_ID and BAMBOO_VPN_TOKEN)
export BAMBOO_VPN_APP_ID="your_app_id"
export BAMBOO_VPN_TOKEN="your_token"
export AGVPN_HELPER_URL="https://example.com/agvpn_helper"  # Optional, if agvpn_helper needs to be downloaded
./docker_run_tests.sh browser

# Run with custom endpoint hostname
ENDPOINT_HOSTNAME="test.local" ./docker_run_tests.sh main
```

## Output

Build artifacts will be placed in the `output` directory (or the directory specified by `OUTPUT_VOLUME`):

### Client Build Output

- `trusttunnel_client` - The built VPN client executable
- Additional test scripts (if present in source)

### Endpoint Build Output

- `trusttunnel_endpoint` - The built VPN endpoint executable (from `build_endpoint.sh`)

### Endpoint Setup Output (from `endpoint_setup.sh`)

- `cert.pem` - SSL certificate
- `key.pem` - SSL private key
- `vpn.conf` - VPN configuration file
- `tls_hosts.conf` - TLS hosts settings file

## Docker Image

The build process uses the `adguard/core-libs:2.8` Docker image, which contains all necessary build dependencies.

### Building Custom Docker Image

You can build a custom Docker image for testing:

```bash
./docker_build.sh image
```

This creates a `core-libs-testing` image that can be used for development and testing.

## Process Management

The test framework uses PID files for robust process lifecycle management:

- **VPN Endpoint**: PID saved to `/output/vpn_endpoint.pid`
- **VPN Client**: PID saved to `/output/vpn_client.pid`
- **Cleanup**: All processes are properly terminated using PID files during cleanup
- **Network Namespaces**: TUN mode tests use the 'tun' network namespace for isolation

## Browser Test Details

The browser tests provide comprehensive network load simulation:

### Features

- **Puppeteer-based**: Uses headless Chrome to simulate real browser traffic
- **Multiple URLs**: Tests against BBC, Google, Guardian, and AdGuard websites
- **Network Disruption**: Simulates network problems and tests VPN reconnection
- **Statistics Collection**: Tracks request counts, errors, response times, and reload statistics
- **Dual Phase Testing**: Runs tests before and after network disruption
- **Real Backend**: Uses `agvpn_helper` to connect to actual VPN backend infrastructure

### Browser Test Output

- `output1part.json` - Test results from the first 30-minute phase
- `output2part.json` - Test results after network disruption and recovery
- Detailed statistics including request timing, error counts, and reload frequencies
