#!/usr/bin/env bash

set -e -x

# This script is used to run integration tests for VPN client and endpoint

# Variables
SELF_DIR_PATH=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
# Image names
COMMON_IMAGE="common-test-image"
CLIENT_IMAGE="standalone-client-image"
CLIENT_WITH_BROWSER_IMAGE="standalone-client-with-browser-image"
ENDPOINT_IMAGE="endpoint-image"
# Directories
ENDPOINT_DIR="endpoint"
VPN_LIBS_ENDPOINT_DIR="vpn-libs-endpoint"
CLIENT_DIR="client"
VPN_LIBS_DIR="vpn-libs"
SIMULATOR_DIR="network-load-simulator"
# Config variables
ENDPOINT_HOSTNAME="endpoint.test"
ENDPOINT_IP=""
ENDPOINT_IPV6=""
MODE="tun"
SOCKS_PORT="7777"
LOG_FILE_NAME="vpn.log"
# Containers
ENDPOINT_CONTAINER=""
CLIENT_CONTAINER=""
COMMON_CONTAINER=""
# Some sensitive variables from bamboo
BAMBOO_CONAN_REPO_URL=""
BAMBOO_VPN_APP_ID=""
BAMBOO_VPN_TOKEN=""
# Config file path
NETWORK_SIMULATOR_CONFIG_FILE="network-load-simulator/config.conf"

# Remove client image if exists
clean_client() {
  if docker image inspect "$CLIENT_IMAGE" > /dev/null 2>&1; then
    docker rmi -f "$CLIENT_IMAGE"
  fi
}

# Remove client with browser image if exists
clean_client_with_browser() {
  if docker image inspect "$CLIENT_WITH_BROWSER_IMAGE" > /dev/null 2>&1; then
    docker rmi -f "$CLIENT_WITH_BROWSER_IMAGE"
  fi
}

# Remove endpoint image if exists
clean_endpoint() {
  if docker image inspect "$ENDPOINT_IMAGE" > /dev/null 2>&1; then
    docker rmi -f "$ENDPOINT_IMAGE"
  fi
}

# Remove common image if exists
clean_common() {
  if docker image inspect "$COMMON_IMAGE" > /dev/null 2>&1; then
    docker rmi -f "$COMMON_IMAGE"
  fi
}

# Remove all networks
clean_network() {
  docker network prune --force
}

# Build common image with all required dependencies
build_common() {
  docker build -t "$COMMON_IMAGE" "$SELF_DIR_PATH"
}

# Build client image with all required dependencies and entrypoint
build_client() {
  docker build \
    --build-arg VPN_LIBS_DIR="$VPN_LIBS_DIR" \
    --build-arg CONAN_REPO_URL="$BAMBOO_CONAN_REPO_URL" \
    -t "$CLIENT_IMAGE" "$SELF_DIR_PATH/$CLIENT_DIR"
}

# Additionally to regular client image, build client with browser contains puppeteer inside with test suite
build_client_with_browser() {
  docker build \
    --build-arg VPN_LIBS_DIR="$VPN_LIBS_DIR" \
    --build-arg CONAN_REPO_URL="$BAMBOO_CONAN_REPO_URL" \
    -t "$CLIENT_WITH_BROWSER_IMAGE" "$SELF_DIR_PATH/$SIMULATOR_DIR"
}

# Rust endpoint image with entrypoint
build_endpoint() {
  docker build \
    --build-arg ENDPOINT_DIR="$VPN_LIBS_ENDPOINT_DIR" \
    --build-arg ENDPOINT_HOSTNAME="$ENDPOINT_HOSTNAME" \
    -t "$ENDPOINT_IMAGE" "$SELF_DIR_PATH/$ENDPOINT_DIR"
}

# Build all required images for regular test
build_all() {
  build_common
  build_client
  build_endpoint
}

build_config_file() {
  # Check that all required variables are set
  if [[ -z "$ENDPOINT_HOSTNAME" ]] || [[ -z "$ENDPOINT_IP" ]] || [[ -z "$ENDPOINT_USERNAME" ]] ||
     [[ -z "$ENDPOINT_PASSWORD" ]] || [[ -z "$BAMBOO_VPN_APP_ID" ]] || [[ -z "$BAMBOO_VPN_TOKEN" ]] ||
     [[ -z "$PROTOCOL" ]] || [[ -z "$MODE" ]] || [[ -z "$LOG_FILE_NAME" ]] || [[ -z "$SOCKS_PORT" ]]; then
    echo "Some of the required variables are not set"
    exit 1
  fi

  # Prepare config file
  echo -e "ENDPOINT_HOSTNAME=${ENDPOINT_HOSTNAME}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "ENDPOINT_IP=${ENDPOINT_IP}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "ENDPOINT_USERNAME=${ENDPOINT_USERNAME}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "ENDPOINT_PASSWORD=${ENDPOINT_PASSWORD}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "APP_ID=${BAMBOO_VPN_APP_ID}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "TOKEN=${BAMBOO_VPN_TOKEN}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "PROTOCOL=${PROTOCOL}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "MODE=${MODE}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "LOG_FILE_NAME=${LOG_FILE_NAME}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "SOCKS_PORT=${SOCKS_PORT}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
}

# Run common container. It might be helpful for running extra bash scripts inside container
run_common() {
  COMMON_CONTAINER=$(docker run --rm -d --entrypoint /bin/bash ${COMMON_IMAGE} -c "while true; do sleep 1000; done")
}

# Run client in TUN mode. Also provide volume for logs.
# In this command vpn-libs is used to run standalone client with TUN mode. After that, test might be run inside container
# todo: Use config file instead of passing all parameters
run_client_tun() {
  PROTOCOL=$1
  LOG_FILE_NAME="vpn_tun_$PROTOCOL.log"
  CLIENT_CONTAINER=$(docker run -d --rm \
    -v $SELF_DIR_PATH/logs:/output \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    --device=/dev/net/tun \
    --add-host="$ENDPOINT_HOSTNAME":"$ENDPOINT_IP" \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.default.disable_ipv6=0 \
    "$CLIENT_IMAGE" \
    "$ENDPOINT_HOSTNAME" "$ENDPOINT_IP" "$ENDPOINT_IPV6" "$PROTOCOL" "$MODE" "$LOG_FILE_NAME")
  echo "Client container run: $CLIENT_CONTAINER"
}

# Run client with browser. This command run vpn-libs inside container and may be used to test with puppeteer
run_client_with_browser() {
  CLIENT_WITH_BROWSER_CONTAINER=$(docker run -d --rm \
    -v $SELF_DIR_PATH/logs:/output \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    --device=/dev/net/tun \
    --add-host="$ENDPOINT_HOSTNAME":"$ENDPOINT_IP" \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    --sysctl net.ipv6.conf.default.disable_ipv6=1 \
    "$CLIENT_WITH_BROWSER_IMAGE" 2>&1)
  echo "Client container with browser run: $CLIENT_WITH_BROWSER_CONTAINER"
}

# Like TUN mode, but for SOCKS
run_client_socks() {
  PROTOCOL=$1
  LOG_FILE_NAME="vpn_socks_$PROTOCOL.log"
  CLIENT_CONTAINER=$(docker run -d --rm \
    -v $SELF_DIR_PATH/logs:/output \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    --add-host="$ENDPOINT_HOSTNAME":"$ENDPOINT_IP" \
    "$CLIENT_IMAGE" \
    "$ENDPOINT_HOSTNAME" "$ENDPOINT_IP" "$ENDPOINT_IPV6" "$PROTOCOL" "$MODE" "$LOG_FILE_NAME" "$SOCKS_PORT")
  echo "Client container run: $CLIENT_CONTAINER"
}

# Run endpoint container. Also has volume for cargo cache to faster build
run_endpoint() {
  ENDPOINT_CONTAINER=$(docker run -d --rm \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    -v $HOME/.cargo:/root/.cargo \
    "$ENDPOINT_IMAGE")
  ENDPOINT_IP=("$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ENDPOINT_CONTAINER")")
  ENDPOINT_IPV6=("$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "$ENDPOINT_CONTAINER")")
  echo "Endpoint created with ipv4: $ENDPOINT_IP, ipv6: $ENDPOINT_IPV6"
}

# Stop all containers in regular test. Because in client with browser test we use real endpoint.
stop_containers() {
  docker stop "$CLIENT_CONTAINER"
  docker stop "$ENDPOINT_CONTAINER"
}

# Call all clean functions
clean() {
  rm -f ${NETWORK_SIMULATOR_CONFIG_FILE}
  clean_common
  clean_network
  clean_client
  clean_endpoint
  docker builder prune -f
}

# Run tests for TUN mode
run_tun_test() {
  build_all
  RESULT=0
  for protocol in http2 http3; do
    run_endpoint
    run_client_tun $protocol
    docker exec -w /test "$ENDPOINT_CONTAINER" iperf3 --server &
    docker exec -w /test "$CLIENT_CONTAINER" ./tun_tests.sh "$ENDPOINT_IP" || RESULT=1
    docker exec "$CLIENT_CONTAINER" chmod -R 777 /output/
    stop_containers
  done
  exit "$RESULT"
}

# Function to get location date from backend via agvpn_helper
get_location_data() {
  location=$(./agvpn_helper get-location -c "Frankfurt" -t "$BAMBOO_VPN_TOKEN")
  ENDPOINT_HOSTNAME=$(echo "$location" | jq -r '.endpoints[0].server_name // empty')
  ENDPOINT_IP=$(echo "$location" | jq -r '.relays[0].relay_ipv4 // empty')
  ENDPOINT_IP=$(echo "$ENDPOINT_IP" | cut -d ":" -f 1)

  # Check that we got location data successfully
  if [[ -z "$ENDPOINT_HOSTNAME" ]] || [[ -z "$ENDPOINT_IP" ]]; then
    echo "Failed to get location data from backend"
    exit 1
  fi
}

# Function to get credentials from backend via agvpn_helper
get_creds() {
  output=$(./agvpn_helper get-creds -t "$BAMBOO_VPN_TOKEN")
  ENDPOINT_USERNAME=$(echo "$output" | jq -r '.username')
  ENDPOINT_PASSWORD=$(echo "$output" | jq -r '.password')

  # Check that we got credentials successfully
  if [[ -z "$ENDPOINT_USERNAME" ]] || [[ -z "$ENDPOINT_PASSWORD" ]]; then
    echo "Failed to get credentials from backend"
    exit 1
  fi
}

# Run tests for client with browser
run_browser_test() {
  # Check that agvpn_helper exists and it is executable
  if [ ! -f agvpn_helper ] || [ ! -x agvpn_helper ]; then
    echo "agvpn_helper not found or not executable"
    exit 1
  fi

  # Build and run common container
  build_common

  # Get location data from backend. Hostname and relay IP address of the endpoint
  get_location_data
  get_creds

  # Prepare config file
  PROTOCOL=http2
  LOG_FILE_NAME="vpn_tun_http2.log"
  MODE="tun"
  build_config_file

  # Build and run client with browser
  build_client_with_browser
  RESULT=0
  run_client_with_browser

  # Check that client is running
  sleep 5
  if ! docker exec "$CLIENT_WITH_BROWSER_CONTAINER" pgrep standalone > /dev/null;
  then
    echo "Client is not running"
    # Try to get some logs from client
    docker logs $CLIENT_WITH_BROWSER_CONTAINER
    exit 1
  fi

  # Run tests for 30 minutes
  docker exec -w /test -e TIME_LIMIT=30m "$CLIENT_WITH_BROWSER_CONTAINER" node index.js || RESULT=1
  docker exec "$CLIENT_WITH_BROWSER_CONTAINER" chmod -R 777 /output/
  docker cp "$CLIENT_WITH_BROWSER_CONTAINER":/test/output.json ./output1part.json

  # Imitate network problems. Drop all traffic to endpoint. Client should reconnect.
  docker exec "$CLIENT_WITH_BROWSER_CONTAINER" /bin/bash -c "iptables -A OUTPUT -j DROP; iptables -A INPUT -j DROP"
  sleep 1
  docker exec "$CLIENT_WITH_BROWSER_CONTAINER" /bin/bash -c 'pids=$(pgrep standalone); echo "PIDS: $pids"; for pid in $pids; do kill -SIGHUP $pid || true; done'
  sleep 9
  docker exec "$CLIENT_WITH_BROWSER_CONTAINER" /bin/bash -c "iptables -D OUTPUT -j DROP; iptables -D INPUT -j DROP"
  sleep 60

  # Run tests again
  docker exec -w /test -e TIME_LIMIT=30m "$CLIENT_WITH_BROWSER_CONTAINER" node index.js || RESULT=1
  docker cp $CLIENT_WITH_BROWSER_CONTAINER:/test/output.json ./output2part.json
  docker stop "$CLIENT_WITH_BROWSER_CONTAINER"
  exit "$RESULT"
}

# Run tests for SOCKS mode
run_socks_test() {
  build_all
  RESULT=0
  for protocol in http2 http3; do
    run_endpoint
    run_client_socks $protocol
    docker exec -w /test "$CLIENT_CONTAINER" ./socks_tests.sh "$ENDPOINT_IP" "$SOCKS_PORT" || RESULT=1
    docker exec "$CLIENT_CONTAINER" chmod -R 777 /output/
    stop_containers
  done
  exit "$RESULT"
}

# Main function to run tests
run() {
  if [[ "$MODE" == "tun" ]]; then
    run_tun_test
  elif [[ "$MODE" == "socks" ]]; then
    run_socks_test
  elif [[ "$MODE" == "browser" ]]; then
    # For browser test we need to get location data and credentials, so we need vpn token and app id to get them
    BAMBOO_VPN_APP_ID=$1
    BAMBOO_VPN_TOKEN=$2
    # Check that all required variables are set
    if [[ -z "$BAMBOO_VPN_APP_ID" ]] || [[ -z "$BAMBOO_VPN_TOKEN" ]]; then
      echo "Some of the required variables are not set"
      exit 1
    fi
    run_browser_test
  fi
}

# Main entrypoint

WORK=$1
if [[ "$WORK" == "run" ]]; then
  MODE=$2
  BAMBOO_CONAN_REPO_URL=$3
  shift 3
  run "$@"
elif [[ "$WORK" == "clean-browser" ]]; then
  clean_client_with_browser
elif [[ "$WORK" == "clean" ]]; then
  clean
fi
