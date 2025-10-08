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

check_iptables() {
  if [ $1 "$(iptables -L OUTPUT -vn | grep $2 | grep $3 | awk '$1 ~ /^[0-9]+$/ && $1 > 0')" ]; then
    echo "...iptables packet count from $2 to $3 matches, passed"
  else
    has_error=`expr $has_error + 1`
    echo "...iptables packet count from $2 to $3 does not match, failed"
  fi
}

echo "Starting iperf3 server"
IPERF_LOCALHOST_ROUTABLE_IP="1.2.3.4"
ip addr add $IPERF_LOCALHOST_ROUTABLE_IP dev lo
iperf3 --server &

echo "Waiting 5 seconds before start"
sleep 5

tunexec() {
  ip netns exec tun "$@"
}

echo "HTTP request -> 1.1.1.1..."
tunexec curl 1.1.1.1 >/dev/null
check_error

echo "HTTP request -> http://1.1.1.1..."
tunexec curl -sS http://1.1.1.1 >/dev/null
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
tunexec curl -sS https://www.cloudflare.com -4 >/dev/null
check_error

echo "HTTP request -> ipv6.google.com, ipv6..."
tunexec curl -6 -sS http://ipv6.google.com >/dev/null
check_error

echo "HTTPS request -> ipv6.google.com, ipv6..."
tunexec curl -6 -sS https://ipv6.google.com >/dev/null
check_error

echo "Download 100MB file..."
tunexec curl -L -O -sS 'https://dtpt-nl-ams-02-144utv0e.adguard.io/speed/100mb.bin' --max-time 120 >/dev/null
check_error

echo "Check ICMP - ping 1.1.1.1 ..."
tunexec ping -c 10 1.1.1.1 &> /dev/null
check_error

echo "Check ICMP - ping 8.8.8.8 ..."
tunexec ping -c 10 8.8.8.8 &> /dev/null
check_error

echo "Check ICMP ipv6 - ping 2a00:1450:4017:814::200e ..."
tunexec ping -c 10 2a00:1450:4017:814::200e &> /dev/null
check_error

echo "Check ICMP ipv6 - ping6 ipv6.google.com ..."
tunexec ping6 -c 10 ipv6.google.com &> /dev/null
check_error

echo "Test UDP with iperf3..."
tunexec iperf3 --udp --client $IPERF_LOCALHOST_ROUTABLE_IP
check_error

echo "Test UDP download with iperf3..."
tunexec iperf3 --udp --reverse --client $IPERF_LOCALHOST_ROUTABLE_IP
check_error

if [ $has_error -gt 0 ]
then
  echo "There were errors"
  exit 1
else
  echo "All tests passed"
  exit 0
fi
