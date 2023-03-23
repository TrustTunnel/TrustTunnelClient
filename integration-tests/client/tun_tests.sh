#!/bin/bash

echo "Integration TUN test start"

ENDPOINT_IP=$1

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

echo "HTTP request -> 1.1.1.1, ipv4..."
curl 1.1.1.1 -4 >/dev/null
check_error
sleep 1

echo "HTTP request -> example.com, ipv4..."
curl http://example.com -4 >/dev/null
check_error
sleep 1

echo "HTTPS request -> https://1.1.1.1, ipv4..."
curl https://1.1.1.1 -4 >/dev/null
check_error
sleep 1

echo "HTTPS request -> example.com, ipv4..."
curl https://example.com -4 >/dev/null
check_error
sleep 1

echo "HTTP request -> ipv6.google.com, ipv6..."
curl http://ipv6.google.com >/dev/null
check_error
sleep 1

echo "HTTPS request -> ipv6.google.com, ipv6..."
curl https://ipv6.google.com >/dev/null
check_error
sleep 1

echo "Download 100MB file..."
curl -O https://speed.hetzner.de/100MB.bin >/dev/null
check_error
sleep 1

echo "Check ICMP - ping 1.1.1.1 ..."
ping -c 10 1.1.1.1 &> /dev/null
check_error
sleep 1

echo "Check ICMP - ping 8.8.8.8 ..."
ping -c 10 8.8.8.8 &> /dev/null
check_error
sleep 1

echo "Check ICMP ipv6 - ping 2a00:1450:4017:814::200e ..."
ping -c 10 2a00:1450:4017:814::200e &> /dev/null
check_error
sleep 1

echo "Check ICMP ipv6 - ping6 ipv6.google.com ..."
ping6 -c 10 ipv6.google.com &> /dev/null
check_error
sleep 1

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