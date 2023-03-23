#!/bin/bash

echo "Integration SOCKS test start"

SOCKS_PORT=$1

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

echo "Check connection..."
nc -vz 127.0.0.1 $SOCKS_PORT >/dev/null
check_error
sleep 1

echo "HTTP request -> 1.1.1.1, ipv4..."
curl -x socks5://127.0.0.1:$SOCKS_PORT 1.1.1.1 >/dev/null
check_error
sleep 1

echo "HTTP request -> example.com, ipv4..."
curl -x socks5://127.0.0.1:$SOCKS_PORT -4 http://example.com >/dev/null
check_error
sleep 1

echo "HTTPs request -> example.com, ipv4..."
curl -x socks5://127.0.0.1:$SOCKS_PORT -4 https://example.com >/dev/null
check_error
sleep 1

echo "HTTP request -> ipv6.google.com, ipv6..."
curl -x socks5h://127.0.0.1:$SOCKS_PORT http://ipv6.google.com >/dev/null
check_error
sleep 1

echo "HTTPS request -> ipv6.google.com, ipv6..."
curl -x socks5h://127.0.0.1:$SOCKS_PORT https://ipv6.google.com >/dev/null
check_error
sleep 1

echo "Download 100MB file..."
curl -x socks5://127.0.0.1:$SOCKS_PORT -O https://speed.hetzner.de/100MB.bin >/dev/null
check_error

if [ $has_error -gt 0 ]
then
    echo "There were errors"
    exit 1
else
    echo "All tests passed"
    exit 0
fi