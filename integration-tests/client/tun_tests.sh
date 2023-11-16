#!/bin/bash

echo "Integration TUN test start"

ENDPOINT_IP=$1
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

echo "HTTP request -> 1.1.1.1..."
curl 1.1.1.1 >/dev/null
check_error

echo "HTTP request -> http://1.1.1.1..."
curl -sS http://1.1.1.1 >/dev/null
check_error

echo "HTTP request to exclusion -> example.org,  ipv4..."
timeout 10 tcpdump -i eth0 host example.org -c 1 > tcp.log &
TCPDUMP_PID=$!
curl -sS example.org -4 --max-time 10 >/dev/null
check_error
check_dump $TCPDUMP_PID

# The case when we get a domain name from server hello.
# The first request should be terminated, and an exclusion is applied when the request is repeated
echo "HTTPS request to exclusion -> https://1.1.1.1 (cloudflare-dns.com)..."
curl -sS https://1.1.1.1 --tlsv1.2 --tls-max 1.2 --max-time 10 >/dev/null
expected_error $CURL_SSL_CONNECT_ERRCODE

echo "HTTPS request to exclusion -> https://1.1.1.1 (cloudflare-dns.com)... (directly)"
timeout 10 tcpdump -i eth0 host 1.1.1.1 -c 1 > tcp.log &
TCPDUMP_PID=$!
curl -sS https://1.1.1.1 --tlsv1.2 --tls-max 1.2 --max-time 10 >/dev/null
check_error
check_dump $TCPDUMP_PID

echo "HTTPS request -> https://www.cloudflare.com, ipv4..."
curl -sS https://www.cloudflare.com -4 >/dev/null
check_error

echo "HTTP request -> ipv6.google.com, ipv6..."
curl -6 -sS http://ipv6.google.com >/dev/null
check_error

echo "HTTPS request -> ipv6.google.com, ipv6..."
curl -6 -sS https://ipv6.google.com >/dev/null
check_error

echo "Download 100MB file..."
curl -L -O -sS 'https://github.com/spacemeowx2/100mb/raw/master/100mb.bin' --max-time 120 >/dev/null
check_error

echo "Check ICMP - ping 1.1.1.1 ..."
ping -c 10 1.1.1.1 &> /dev/null
check_error

echo "Check ICMP - ping 8.8.8.8 ..."
ping -c 10 8.8.8.8 &> /dev/null
check_error

echo "Check ICMP ipv6 - ping 2a00:1450:4017:814::200e ..."
ping -c 10 2a00:1450:4017:814::200e &> /dev/null
check_error

echo "Check ICMP ipv6 - ping6 ipv6.google.com ..."
ping6 -c 10 ipv6.google.com &> /dev/null
check_error

echo "Test UDP with iperf3..."
iperf3 --udp --client "$ENDPOINT_IP"
check_error

echo "Test UDP download with iperf3..."
iperf3 --udp --reverse --client "$ENDPOINT_IP"
check_error

if [ $has_error -gt 0 ]
then
  echo "There were errors"
  exit 1
else
  echo "All tests passed"
  exit 0
fi
