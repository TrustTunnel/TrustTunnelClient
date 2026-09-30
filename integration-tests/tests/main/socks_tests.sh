#!/bin/bash

echo "Integration SOCKS test start"

ENDPOINT_IP=$1
SOCKS_PORT=$2
CURL_SSL_CONNECT_ERRCODE=35

declare -i has_error
has_error=0

# The downloaded size is verified, so an error page or a truncated transfer
# cannot pass as a successful download.
SPEED_TEST_URL="${SPEED_TEST_URL:-https://dtpt-nl-ams-02-144utv0e.adguard.io/speed/100mb.bin}"
SPEED_TEST_MIN_BYTES="${SPEED_TEST_MIN_BYTES:-100000000}"

check_error() {
  if [ $? -eq 0 ]
  then
    echo "...Passed"
  else
    has_error=`expr $has_error + 1`
    echo "...Failed"
  fi
}

expected_error() {
  if [ $? -eq $1 ]
  then
    echo "...Passed"
  else
    has_error=`expr $has_error + 1`
    echo "...Failed"
  fi
}

check_iptables() {
  if [ $1 "$(iptables -L OUTPUT -vn | grep $2 | grep $3 | awk '$1 ~ /^[0-9]+$/ && $1 > 0')" ]; then
    echo "...iptables packet count from $2 to $3 matches, passed"
  else
    has_error=`expr $has_error + 1`
    echo "...iptables packet count from $2 to $3 does not match, failed"
  fi
}

sleep 5

echo "Check connection..."
nc -vz -w 5 127.0.0.1 $SOCKS_PORT >/dev/null
check_error

echo "HTTP request -> 1.1.1.1..."
curl -sS --connect-timeout 10 --max-time 30 -x socks5://127.0.0.1:$SOCKS_PORT 1.1.1.1 >/dev/null
check_error

echo "HTTP request to exclusion -> example.org,  ipv4..."
iptables -Z OUTPUT
curl -sS -x socks5://127.0.0.1:$SOCKS_PORT httpbin.agrd.dev -4 --max-time 10 >/dev/null
check_error
check_iptables -n /client httpbin.agrd.dev
check_iptables -z /endpoint httpbin.agrd.dev

# The case when we get a domain name from server hello.
# The first request should be terminated, and an exclusion is applied when the request is repeated
echo "HTTPS request to exclusion -> https://1.1.1.1 (cloudflare-dns.com)..."
curl -sS -x socks5h://127.0.0.1:$SOCKS_PORT --tlsv1.2 --tls-max 1.2 --max-time 10 https://1.1.1.1 >/dev/null
expected_error $CURL_SSL_CONNECT_ERRCODE

echo "HTTPS request to exclusion -> https://1.1.1.1 (cloudflare-dns.com)... (directly)"
iptables -Z OUTPUT
curl -sS -x socks5h://127.0.0.1:$SOCKS_PORT --tlsv1.2 --tls-max 1.2 --max-time 10 https://1.1.1.1 >/dev/null
check_error
check_iptables -n /client 1.1.1.1
check_iptables -z /endpoint 1.1.1.1

echo "HTTPS request -> cloudflare.com, ipv4..."
curl -sS --connect-timeout 10 --max-time 30 -x socks5://127.0.0.1:$SOCKS_PORT -4 https://www.cloudflare.com >/dev/null
check_error

echo "SOCKS request with IPv4 as a domain name -> http://1.1.1.1 ..."
curl -sS --connect-timeout 10 --max-time 30 -x socks5h://127.0.0.1:$SOCKS_PORT http://1.1.1.1 >/dev/null
check_error

echo "SOCKS request with IPv6 as a domain name -> http://[2606:4700:4700::1111]/ ..."
curl -sS --connect-timeout 10 --max-time 30 -x socks5h://127.0.0.1:$SOCKS_PORT http://[2606:4700:4700::1111]/ >/dev/null
check_error

echo "HTTP request -> ipv6.google.com, ipv6..."
curl -sS --connect-timeout 10 --max-time 30 -x socks5h://127.0.0.1:$SOCKS_PORT http://ipv6.google.com >/dev/null
check_error

echo "HTTPS request -> ipv6.google.com, ipv6..."
curl -sS --connect-timeout 10 --max-time 30 -x socks5h://127.0.0.1:$SOCKS_PORT https://ipv6.google.com >/dev/null
check_error

echo "Download 100MB file..."
SPEED_TEST_BYTES="$(curl -sS -L -o /dev/null -w '%{size_download}' --connect-timeout 10 --max-time 120 \
  -x socks5://127.0.0.1:$SOCKS_PORT "$SPEED_TEST_URL" | tail -n1)"
SPEED_TEST_BYTES="${SPEED_TEST_BYTES%%.*}"
if [ "${SPEED_TEST_BYTES:-0}" -ge "$SPEED_TEST_MIN_BYTES" ]; then
  echo "...passed: downloaded $SPEED_TEST_BYTES bytes"
else
  echo "...failed: downloaded ${SPEED_TEST_BYTES:-0} bytes, expected at least $SPEED_TEST_MIN_BYTES"
  has_error=$((has_error + 1))
fi

if [ $has_error -gt 0 ]
then
  echo "There were errors"
  exit 1
else
  echo "All tests passed"
  exit 0
fi
