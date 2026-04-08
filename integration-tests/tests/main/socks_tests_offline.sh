#!/usr/bin/env bash

set -x

SOCKS_PORT="$2"
has_error=0

check_error() {
  if [ $? -eq 0 ]; then
    echo "...passed"
  else
    has_error=$((has_error + 1))
    echo "...failed"
  fi
}

echo "Check SOCKS port readiness"
SOCKS_READY=0
for _ in $(seq 1 10); do
  if nc -z 127.0.0.1 "$SOCKS_PORT" >/dev/null 2>&1; then
    SOCKS_READY=1
    break
  fi
  sleep 1
done

if [ "$SOCKS_READY" -eq 1 ]; then
  echo "...passed"
else
  has_error=$((has_error + 1))
  echo "...failed"
fi

echo "Start local HTTP server for offline SOCKS check"
OFFLINE_HTTP_ROOT="/tmp/offline_socks_http_root"
mkdir -p "$OFFLINE_HTTP_ROOT"
truncate -s 100M "$OFFLINE_HTTP_ROOT/100mb.bin"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$OFFLINE_HTTP_ROOT" >/tmp/offline_http_server.log 2>&1 &
HTTP_SERVER_PID=$!

cleanup() {
  kill "$HTTP_SERVER_PID" 2>/dev/null || true
  rm -rf "$OFFLINE_HTTP_ROOT"
}
trap cleanup EXIT

sleep 1

echo "HTTP request via SOCKS to local server"
curl -sS -x socks5h://127.0.0.1:"$SOCKS_PORT" http://127.0.0.1:18080 >/dev/null
check_error

echo "HTTP request via SOCKS5 (without remote DNS) to local server"
curl -sS -x socks5://127.0.0.1:"$SOCKS_PORT" http://127.0.0.1:18080 >/dev/null
check_error

echo "Download local 100MB file via SOCKS"
curl -sS -x socks5h://127.0.0.1:"$SOCKS_PORT" -L -o /dev/null http://127.0.0.1:18080/100mb.bin --max-time 60
check_error

echo "Negative check: unreachable test host should fail quickly"
if curl -sS -x socks5h://127.0.0.1:"$SOCKS_PORT" http://offline.invalid --max-time 3 >/dev/null; then
  has_error=$((has_error + 1))
  echo "...failed (expected offline.invalid to fail)"
else
  echo "...passed (offline.invalid failed as expected)"
fi

if [ $has_error -gt 0 ]
then
  echo "There were errors"
  exit 1
else
  echo "All offline SOCKS tests passed"
  exit 0
fi
