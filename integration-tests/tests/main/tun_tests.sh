#!/bin/bash

echo "Integration TUN test start"

ENDPOINT_IP=$1
CURL_SSL_CONNECT_ERRCODE=35

declare -i has_error
has_error=0

tunexec_timeout() {
  local seconds="$1"
  shift
  timeout "$seconds" ip netns exec tun "$@"
}

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

IPERF_LOCALHOST_ROUTABLE_IP="1.2.3.4"
ip addr add $IPERF_LOCALHOST_ROUTABLE_IP dev lo || true

echo "Waiting 5 seconds before start"
sleep 5

tunexec() {
  ip netns exec tun "$@"
}

echo "HTTP request -> 1.1.1.1..."
tunexec curl -sS --connect-timeout 10 --max-time 30 1.1.1.1 >/dev/null
check_error

echo "HTTP request -> http://1.1.1.1..."
tunexec curl -sS --connect-timeout 10 --max-time 30 http://1.1.1.1 >/dev/null
check_error

echo "HTTP request to exclusion -> httpbin.agrd.dev,  ipv4..."
iptables -Z OUTPUT
tunexec curl -sS httpbin.agrd.dev -4 --max-time 10 >/dev/null
check_error
check_iptables -n /client httpbin.agrd.dev
check_iptables -z /endpoint httpbin.agrd.dev

# The case when we get a domain name from server hello.
# The first request should be terminated, and an exclusion is applied when the request is repeated
echo "HTTPS request to exclusion -> https://1.1.1.1 (cloudflare-dns.com)..."
tunexec curl -sS https://1.1.1.1 --tlsv1.2 --tls-max 1.2 --max-time 10 >/dev/null
expected_error $CURL_SSL_CONNECT_ERRCODE

echo "HTTPS request to exclusion -> https://1.1.1.1 (cloudflare-dns.com)... (directly)"
iptables -Z OUTPUT
tunexec curl -sS https://1.1.1.1 --tlsv1.2 --tls-max 1.2 --max-time 10 >/dev/null
check_error
check_iptables -n /client 1.1.1.1
check_iptables -z /endpoint 1.1.1.1

echo "HTTPS request -> https://www.cloudflare.com, ipv4..."
tunexec curl -sS --connect-timeout 10 --max-time 30 https://www.cloudflare.com -4 >/dev/null
check_error

echo "HTTP request -> ipv6.google.com, ipv6..."
tunexec curl -sS --connect-timeout 10 --max-time 30 -6 http://ipv6.google.com >/dev/null
check_error

echo "HTTPS request -> ipv6.google.com, ipv6..."
tunexec curl -sS --connect-timeout 10 --max-time 30 -6 https://ipv6.google.com >/dev/null
check_error

echo "Download 100MB file..."
SPEED_TEST_BYTES="$(tunexec curl -sS -L -o /dev/null -w '%{size_download}' --connect-timeout 10 --max-time 120 "$SPEED_TEST_URL" | tail -n1)"
SPEED_TEST_BYTES="${SPEED_TEST_BYTES%%.*}"
if [ "${SPEED_TEST_BYTES:-0}" -ge "$SPEED_TEST_MIN_BYTES" ]; then
  echo "...passed: downloaded $SPEED_TEST_BYTES bytes"
else
  echo "...failed: downloaded ${SPEED_TEST_BYTES:-0} bytes, expected at least $SPEED_TEST_MIN_BYTES"
  has_error=$((has_error + 1))
fi

echo "Check ICMP - ping 1.1.1.1 ..."
tunexec_timeout 60 ping -c 10 1.1.1.1 > /dev/null
check_error

echo "Check ICMP - ping 8.8.8.8 ..."
tunexec_timeout 60 ping -c 10 8.8.8.8 > /dev/null
check_error

echo "Check ICMP ipv6 - ping 2001:4860:4860::8888 ..."
tunexec_timeout 60 ping -c 10 2001:4860:4860::8888 > /dev/null
check_error

echo "Check ICMP ipv6 - ping6 ipv6.google.com ..."
tunexec_timeout 60 ping6 -c 10 ipv6.google.com > /dev/null
check_error

# An iperf3 server runs one test at a time, so each test gets its own --one-off
# instance; otherwise the second client hits "the server is busy".
echo "Test UDP with iperf3..."
iperf3 --server --one-off --port 5201 > /tmp/iperf_upload.log 2>&1 &
IPERF_UPLOAD_PID=$!
sleep 1
tunexec_timeout 120 iperf3 --udp --client $IPERF_LOCALHOST_ROUTABLE_IP --port 5201
check_error
wait "$IPERF_UPLOAD_PID" 2>/dev/null || true

echo "Test UDP download with iperf3..."
iperf3 --server --one-off --port 5202 > /tmp/iperf_reverse.log 2>&1 &
IPERF_REVERSE_PID=$!
sleep 1
tunexec_timeout 120 iperf3 --udp --reverse --client $IPERF_LOCALHOST_ROUTABLE_IP --port 5202
check_error
wait "$IPERF_REVERSE_PID" 2>/dev/null || true

if [ $has_error -gt 0 ]
then
  echo "There were errors"
  exit 1
else
  echo "All tests passed"
  exit 0
fi
