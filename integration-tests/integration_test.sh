#!/usr/bin/env bash

set -e -x

SELF_DIR_PATH=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

COMMON_IMAGE="common-test-image"
CLIENT_IMAGE="standalone-client-image"
CLIENT_WITH_BROWSER_IMAGE="standalone-client-with-browser-image"

ENDPOINT_IMAGE="endpoint-image"

ENDPOINT_DIR="endpoint"
VPN_LIBS_ENDPOINT_DIR="vpn-libs-endpoint"

CLIENT_DIR="client"
VPN_LIBS_DIR="vpn-libs"
SIMULATOR_DIR="network-load-simulator"

ENDPOINT_HOSTNAME="endpoint.test"
ENDPOINT_IP=""
ENDPOINT_IPV6=""

MODE="tun"
SOCKS_PORT="7777"
LOG_FILE_NAME="vpn.log"

ENDPOINT_CONTAINER=""
CLIENT_CONTAINER=""
COMMON_CONTAINER=""

ADGUARD_API_DOMAIN=""
ADGUARD_API_CREDS_URL=""
ADGUARD_API_LOCATIONS_URL=""

BAMBOO_CONAN_REPO_URL=""
BAMBOO_VPN_APP_ID=""
BAMBOO_VPN_TOKEN=""
BAMBOO_ADGUARD_API_CREDS_PATH=""
BAMBOO_ADGUARD_API_LOCATIONS_PATH=""
BAMBOO_ADGUARD_API_DOMAIN=""
BAMBOO_ADGUARD_RELAY_IP=""

NETWORK_SIMULATOR_CONFIG_FILE="network-load-simulator/config.conf"

clean_client() {
  if docker image inspect "$CLIENT_IMAGE" > /dev/null 2>&1; then
    docker rmi -f "$CLIENT_IMAGE"
  fi
}

clean_client_with_image() {
  if docker image inspect "$CLIENT_WITH_BROWSER_IMAGE" > /dev/null 2>&1; then
    docker rmi -f "$CLIENT_WITH_BROWSER_IMAGE"
  fi
}

clean_endpoint() {
  if docker image inspect "$ENDPOINT_IMAGE" > /dev/null 2>&1; then
    docker rmi -f "$ENDPOINT_IMAGE"
  fi
}

clean_common() {
  if docker image inspect "$COMMON_IMAGE" > /dev/null 2>&1; then
    docker rmi -f "$COMMON_IMAGE"
  fi
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

build_client_with_browser() {
  docker build \
    --build-arg VPN_LIBS_DIR="$VPN_LIBS_DIR" \
    --build-arg CONAN_REPO_URL="$BAMBOO_CONAN_REPO_URL" \
    -t "$CLIENT_WITH_BROWSER_IMAGE" "$SELF_DIR_PATH/$SIMULATOR_DIR"
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

build_config_file() {
  echo -e "ENDPOINT_HOSTNAME=${ENDPOINT_HOSTNAME}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "ENDPOINT_IP=${ENDPOINT_IP}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "APP_ID=${BAMBOO_VPN_APP_ID}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "TOKEN=${BAMBOO_VPN_TOKEN}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "CREDS_API_URL=${ADGUARD_API_CREDS_URL}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "PROTOCOL=${PROTOCOL}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "MODE=${MODE}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "LOG_FILE_NAME=${LOG_FILE_NAME}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
  echo -e "SOCKS_PORT=${SOCKS_PORT}" >> ${NETWORK_SIMULATOR_CONFIG_FILE}
}

run_common() {
  COMMON_CONTAINER=$(docker run --rm -d --entrypoint /bin/bash ${COMMON_IMAGE} -c "while true; do sleep 1000; done")
}

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

stop_containers() {
  docker stop "$CLIENT_CONTAINER"
  docker stop "$ENDPOINT_CONTAINER"
}

clean() {
  rm -f ${NETWORK_SIMULATOR_CONFIG_FILE}
  clean_common
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
    docker exec "$CLIENT_CONTAINER" chmod -R 777 /output/
    stop_containers
  done
  exit "$RESULT"
}

get_location_data() {
    docker cp network-load-simulator/get_location.sh ${COMMON_CONTAINER}:get_location.sh
    docker exec ${COMMON_CONTAINER} /bin/bash -c "bash ./get_location.sh ${ADGUARD_API_LOCATIONS_URL}"
    docker cp ${COMMON_CONTAINER}:result.txt network-load-simulator/endpoint.txt
    ENDPOINT_HOSTNAME=$(cat network-load-simulator/endpoint.txt | grep ENDPOINT_HOSTNAME | cut -d '=' -f 2)
    ENDPOINT_IP=$BAMBOO_ADGUARD_RELAY_IP
    docker stop ${COMMON_CONTAINER}
    rm -f network-load-simulator/endpoint.txt
}

run_browser_test() {
  build_common
  run_common

  ADGUARD_API_DOMAIN=$BAMBOO_ADGUARD_API_DOMAIN
  ADGUARD_API_CREDS_URL="https://${ADGUARD_API_DOMAIN}${BAMBOO_ADGUARD_API_CREDS_PATH}"
  ADGUARD_API_LOCATIONS_URL="https://${ADGUARD_API_DOMAIN}${BAMBOO_ADGUARD_API_LOCATIONS_PATH}"
  get_location_data

  PROTOCOL=http2
  LOG_FILE_NAME="vpn_tun_http2.log"
  MODE="tun"
  build_config_file
  build_client_with_browser

  RESULT=0
  run_client_with_browser

  sleep 5
  docker exec -w /test -e TIME_LIMIT=30m "$CLIENT_WITH_BROWSER_CONTAINER" node index.js || RESULT=1
  docker exec "$CLIENT_WITH_BROWSER_CONTAINER" chmod -R 777 /output/
  docker cp "$CLIENT_WITH_BROWSER_CONTAINER":/test/output.json ./output1part.json

  docker exec "$CLIENT_WITH_BROWSER_CONTAINER" /bin/bash -c "iptables -A OUTPUT -j DROP; iptables -A INPUT -j DROP"
  sleep 1
  docker exec "$CLIENT_WITH_BROWSER_CONTAINER" /bin/bash -c 'pids=$(pgrep standalone); echo "PIDS: $pids"; for pid in $pids; do kill -SIGHUP $pid || true; done'
  sleep 9
  docker exec "$CLIENT_WITH_BROWSER_CONTAINER" /bin/bash -c "iptables -D OUTPUT -j DROP; iptables -D INPUT -j DROP"
  sleep 60

  docker exec -w /test -e TIME_LIMIT=30m "$CLIENT_WITH_BROWSER_CONTAINER" node index.js || RESULT=1
  docker cp $CLIENT_WITH_BROWSER_CONTAINER:/test/output.json ./output2part.json
  docker stop "$CLIENT_WITH_BROWSER_CONTAINER"
  exit "$RESULT"
}

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

run() {
  if [[ "$MODE" == "tun" ]]; then
    run_tun_test
  elif [[ "$MODE" == "socks" ]]; then
    run_socks_test
  elif [[ "$MODE" == "browser" ]]; then
    BAMBOO_VPN_APP_ID=$1
    BAMBOO_VPN_TOKEN=$2
    BAMBOO_ADGUARD_API_CREDS_PATH=$3
    BAMBOO_ADGUARD_API_LOCATIONS_PATH=$4
    BAMBOO_ADGUARD_API_DOMAIN=$5
    BAMBOO_ADGUARD_RELAY_IP=$6
    run_browser_test
  fi
}

WORK=$1
if [[ "$WORK" == "run" ]]; then
  MODE=$2
  BAMBOO_CONAN_REPO_URL=$3
  shift 3
  run "$@"
elif [[ "$WORK" == "clean-browser" ]]; then
  clean_client_with_image
elif [[ "$WORK" == "clean" ]]; then
  clean
fi
