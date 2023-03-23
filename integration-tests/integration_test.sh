#!/usr/bin/env bash

set -e -x

SELF_DIR_PATH=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

COMMON_IMAGE="common-test-image"
CLIENT_IMAGE="standalone-client-image"
ENDPOINT_IMAGE="endpoint-image"

ENDPOINT_DIR="endpoint"
VPN_LIBS_ENDPOINT_DIR="vpn-libs-endpoint"

CLIENT_DIR="client"
VPN_LIBS_DIR="vpn-libs"

ENDPOINT_HOSTNAME="endpoint.test"
ENDPOINT_IP=""
ENDPOINT_IPV6=""

NETWORK_NAME="test-network"
MODE="tun"
SOCKS_PORT="7777"

ENDPOINT_CONTAINER=""
CLIENT_CONTAINER=""

BAMBOO_CONAN_REPO_URL=""

clean_client() {
  docker rmi -f "$CLIENT_IMAGE"
}

clean_endpoint() {
  docker rmi -f "$ENDPOINT_IMAGE"
}

clean_network() {
  docker network prune --force
}

build_common() {
  docker build -t "$COMMON_IMAGE" "$SELF_DIR_PATH"
}

build_client() {
  docker build \
    --build-arg VPN_LIBS_DIR="$VPN_LIBS_DIR" \
    --build-arg CONAN_REPO_URL="$BAMBOO_CONAN_REPO_URL" \
    -t "$CLIENT_IMAGE" "$SELF_DIR_PATH/$CLIENT_DIR"
}

build_endpoint() {
  docker build \
    --build-arg ENDPOINT_DIR="$VPN_LIBS_ENDPOINT_DIR" \
    --build-arg ENDPOINT_HOSTNAME="$ENDPOINT_HOSTNAME" \
    -t "$ENDPOINT_IMAGE" "$SELF_DIR_PATH/$ENDPOINT_DIR"
}

build_all() {
  build_common
  build_client
  build_endpoint
}

run_client_tun() {
  PROTOCOL=$1
  CLIENT_CONTAINER=$(docker run -d --rm \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    --device=/dev/net/tun \
    --add-host="$ENDPOINT_HOSTNAME":"$ENDPOINT_IP" \
    "$CLIENT_IMAGE" \
    "$ENDPOINT_HOSTNAME" "$ENDPOINT_IP" "$ENDPOINT_IPV6" "$PROTOCOL" "$MODE")
  echo "Client container run: $CLIENT_CONTAINER"
}

run_client_socks() {
  PROTOCOL=$1
  CLIENT_CONTAINER=$(docker run -d --rm \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    --add-host="$ENDPOINT_HOSTNAME":"$ENDPOINT_IP" \
    "$CLIENT_IMAGE" \
    "$ENDPOINT_HOSTNAME" "$ENDPOINT_IP" "$ENDPOINT_IPV6" "$PROTOCOL" "$MODE" "$SOCKS_PORT")
  echo "Client container run: $CLIENT_CONTAINER"
}

run_endpoint() {
  ENDPOINT_CONTAINER=$(docker run -d --rm \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    "$ENDPOINT_IMAGE")
  ENDPOINT_IP=("$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ENDPOINT_CONTAINER")")
  ENDPOINT_IPV6=("$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "$ENDPOINT_CONTAINER")")
  echo "Endpoint created with ipv4: $ENDPOINT_IP, ipv6: $ENDPOINT_IPV6"
}

stop_containers() {
  docker stop "$CLIENT_CONTAINER"
  docker stop "$ENDPOINT_CONTAINER"
}

clean() {
  clean_network
  clean_client
  clean_endpoint
  docker builder prune -f
}

run_tun_test() {
  build_all
  RESULT=0
  for protocol in http2 http3; do
    run_endpoint
    run_client_tun $protocol
    docker exec -w /test "$ENDPOINT_CONTAINER" iperf3 --server &
    docker exec -w /test "$CLIENT_CONTAINER" ./tun_tests.sh "$ENDPOINT_IP" || RESULT=1
    stop_containers
  done
  exit "$RESULT"
}

run_socks_test() {
  build_all
  RESULT=0
  for protocol in http2 http3; do
    run_endpoint
    run_client_socks $protocol
    docker exec -w /test "$CLIENT_CONTAINER" ./socks_tests.sh "$SOCKS_PORT" || RESULT=1
    stop_containers
  done
  exit "$RESULT"
}

run() {
  if [[ "$MODE" == "tun" ]]; then
    run_tun_test
  elif [[ "$MODE" == "socks" ]]; then
    run_socks_test
  fi
}

WORK=$1
if [[ "$WORK" == "run" ]]; then
  MODE=$2
  BAMBOO_CONAN_REPO_URL=$3
  run
elif [[ "$WORK" == "clean" ]]; then
  clean
fi