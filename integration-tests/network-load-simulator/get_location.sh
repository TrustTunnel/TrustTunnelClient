#!/usr/bin/env bash

LOCATIONS_API_URL=$1
LOCATIONS=""

echo "nameserver 101.101.101.101" > /etc/resolv.conf

for i in {1..6}; do
  LOCATIONS=$(timeout 10s ~/go/bin/gocurl --tls-split-hello=5:50 "${LOCATIONS_API_URL}")

  if [[ ! -z "$LOCATIONS" ]]; then
    break
  fi
  sleep 1
done

if [[ -z "$LOCATIONS" ]]; then
  echo "Failed to fetch data."
  exit 1
fi

ENDPOINT_HOSTNAME=$(echo $LOCATIONS | jq -r '.locations[] | select(.city_name=="Frankfurt") | .endpoints[0] | .server_name')
ENDPOINT_IP=$(echo $LOCATIONS | jq -r '.locations[] | select(.city_name=="Frankfurt") | .relay_endpoints[0] | .ipv4_address')

echo "ENDPOINT_HOSTNAME=${ENDPOINT_HOSTNAME}" >> result.txt
echo "ENDPOINT_IP=${ENDPOINT_IP}" >> result.txt
