#!/bin/bash

echo "Integration SOCKS test start"

ENDPOINT_IP=$1
SOCKS_PORT=$2
CURL_SSL_CONNECT_ERRCODE=35

declare -i has_error
has_error=0

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

check_dump() {
  wait $1
  if [ -s tcp.log ]; then
      echo "...tcpdump isn't empty, passed"
    else
      has_error=`expr $has_error + 1`
      echo "...tcpdump is empty, failed"
  fi
}

sleep 5

echo "Check connection..."
nc -vz 127.0.0.1 $SOCKS_PORT >/dev/null
check_error

echo "HTTP request -> 1.1.1.1..."
curl -sS -x socks5://127.0.0.1:$SOCKS_PORT 1.1.1.1 >/dev/null
check_error

echo "HTTP request to exclusion -> example.org,  ipv4..."
timeout 10 tcpdump -i eth0 host example.org -c 1 > tcp.log &
TCPDUMP_PID=$!
curl -sS -x socks5://127.0.0.1:$SOCKS_PORT example.org -4 --max-time 10 >/dev/null
check_error
check_dump $TCPDUMP_PID

# The case when we get a domain name from server hello.
# The first request should be terminated, and an exclusion is applied when the request is repeated
echo "HTTPS request to exclusion -> https://1.1.1.1 (cloudflare-dns.com)..."
curl -sS -x socks5h://127.0.0.1:$SOCKS_PORT --tlsv1.2 --tls-max 1.2 --max-time 10 https://1.1.1.1 >/dev/null
expected_error $CURL_SSL_CONNECT_ERRCODE

echo "HTTPS request to exclusion -> https://1.1.1.1 (cloudflare-dns.com)... (directly)"
timeout 10 tcpdump -i eth0 host 1.1.1.1 -c 1 > tcp.log &
TCPDUMP_PID=$!
curl -sS -x socks5h://127.0.0.1:$SOCKS_PORT --tlsv1.2 --tls-max 1.2 --max-time 10 https://1.1.1.1 >/dev/null
check_error
check_dump $TCPDUMP_PID

echo "HTTPS request -> cloudflare.com, ipv4..."
curl -sS -x socks5://127.0.0.1:$SOCKS_PORT -4 https://www.cloudflare.com >/dev/null
check_error

echo "SOCKS request with IPv4 as a domain name -> http://1.1.1.1 ..."
curl -sS -x socks5h://127.0.0.1:$SOCKS_PORT http://1.1.1.1 >/dev/null
check_error

echo "SOCKS request with IPv6 as a domain name -> http://[2606:4700:4700::1111]/ ..."
curl -sS -x socks5h://127.0.0.1:$SOCKS_PORT http://[2606:4700:4700::1111]/ >/dev/null
check_error

echo "HTTP request -> ipv6.google.com, ipv6..."
curl -sS -x socks5h://127.0.0.1:$SOCKS_PORT http://ipv6.google.com >/dev/null
check_error

echo "HTTPS request -> ipv6.google.com, ipv6..."
curl -sS -x socks5h://127.0.0.1:$SOCKS_PORT https://ipv6.google.com >/dev/null
check_error

echo "Download 100MB file..."
curl -sS -x socks5://127.0.0.1:$SOCKS_PORT -O 'https://speedtest-fkt-eqx.retn.net.prod.hosts.ooklaserver.net:8080/download?size=100000000' --max-time 120 >/dev/null
check_error

if [ $has_error -gt 0 ]
then
  echo "There were errors"
  exit 1
else
  echo "All tests passed"
  exit 0
fi
