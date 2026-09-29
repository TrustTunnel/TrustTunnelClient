#!/bin/bash

echo "Integration SOCKS test start"

ENDPOINT_IP=$1
SOCKS_PORT=$2
CURL_SSL_CONNECT_ERRCODE=35
# External services may fail transiently, so network checks are retried.
RETRY_ATTEMPTS="${RETRY_ATTEMPTS:-3}"
RETRY_DELAY="${RETRY_DELAY:-5}"

declare -i has_error
has_error=0

retry() {
  local attempt=1
  local rc=0
  while true; do
    "$@" && return 0
    rc=$?
    if [ "$attempt" -ge "$RETRY_ATTEMPTS" ]; then
      echo "Command failed after $RETRY_ATTEMPTS attempts (exit code: $rc): $*" >&2
      return "$rc"
    fi
    echo "Attempt $attempt/$RETRY_ATTEMPTS failed (exit code: $rc), retrying in ${RETRY_DELAY}s: $*" >&2
    sleep "$RETRY_DELAY"
    attempt=$((attempt + 1))
  done
}

# Speed-test candidates: our own node first, then independent fallbacks; the
# download is verified by size, so the files may differ.
SPEED_TEST_URLS="${SPEED_TEST_URLS:-https://dtpt-nl-ams-02-144utv0e.adguard.io/speed/100mb.bin https://proof.ovh.net/files/100Mb.dat https://ash-speed.hetzner.com/100MB.bin https://nbg1-speed.hetzner.com/100MB.bin}"
SPEED_TEST_MIN_BYTES="${SPEED_TEST_MIN_BYTES:-100000000}"

# Pick the first speed-test host that answers; the arguments are the curl prefix
# (e.g. "curl -x socks5://..."). The probe is bounded: some hosts ignore Range.
probe_speed_test_url() {
  local url code
  for url in $SPEED_TEST_URLS; do
    code="$("$@" -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 3 -r 0-1023 "$url" 2>/dev/null | tail -n1)"
    if [ "$code" = "200" ] || [ "$code" = "206" ]; then
      echo "$url"
      return 0
    fi
    echo "Speed-test host is not reachable, trying the next one: $url (http code: ${code:-none})" >&2
  done
  return 1
}

echo "Retry policy: up to $RETRY_ATTEMPTS attempts with ${RETRY_DELAY}s delay for network checks"

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
retry nc -vz -w 5 127.0.0.1 $SOCKS_PORT >/dev/null
check_error

echo "HTTP request -> 1.1.1.1..."
retry curl -sS --connect-timeout 10 --max-time 30 -x socks5://127.0.0.1:$SOCKS_PORT 1.1.1.1 >/dev/null
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
retry curl -sS --connect-timeout 10 --max-time 30 -x socks5://127.0.0.1:$SOCKS_PORT -4 https://www.cloudflare.com >/dev/null
check_error

echo "SOCKS request with IPv4 as a domain name -> http://1.1.1.1 ..."
retry curl -sS --connect-timeout 10 --max-time 30 -x socks5h://127.0.0.1:$SOCKS_PORT http://1.1.1.1 >/dev/null
check_error

echo "SOCKS request with IPv6 as a domain name -> http://[2606:4700:4700::1111]/ ..."
retry curl -sS --connect-timeout 10 --max-time 30 -x socks5h://127.0.0.1:$SOCKS_PORT http://[2606:4700:4700::1111]/ >/dev/null
check_error

echo "HTTP request -> ipv6.google.com, ipv6..."
retry curl -sS --connect-timeout 10 --max-time 30 -x socks5h://127.0.0.1:$SOCKS_PORT http://ipv6.google.com >/dev/null
check_error

echo "HTTPS request -> ipv6.google.com, ipv6..."
retry curl -sS --connect-timeout 10 --max-time 30 -x socks5h://127.0.0.1:$SOCKS_PORT https://ipv6.google.com >/dev/null
check_error

echo "Download 100MB file..."
SPEED_TEST_URL="$(probe_speed_test_url curl -x socks5://127.0.0.1:$SOCKS_PORT || true)"
if [ -z "$SPEED_TEST_URL" ]; then
  echo "...failed: no reachable speed-test host"
  has_error=$((has_error + 1))
else
  SPEED_TEST_BYTES="$(curl -sS -L -o /dev/null -w '%{size_download}' --connect-timeout 10 --max-time 120 \
    --retry 2 --retry-delay 5 --retry-all-errors -x socks5://127.0.0.1:$SOCKS_PORT "$SPEED_TEST_URL" | tail -n1)"
  SPEED_TEST_BYTES="${SPEED_TEST_BYTES%%.*}"
  if [ "${SPEED_TEST_BYTES:-0}" -ge "$SPEED_TEST_MIN_BYTES" ]; then
    echo "...passed: downloaded $SPEED_TEST_BYTES bytes from $SPEED_TEST_URL"
  else
    echo "...failed: downloaded ${SPEED_TEST_BYTES:-0} bytes from $SPEED_TEST_URL, expected at least $SPEED_TEST_MIN_BYTES"
    has_error=$((has_error + 1))
  fi
fi

if [ $has_error -gt 0 ]
then
  echo "There were errors"
  exit 1
else
  echo "All tests passed"
  exit 0
fi
