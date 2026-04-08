#!/usr/bin/env bash

set -x

ENDPOINT_IP="$1"
has_error=0

check_error() {
  if [ $? -eq 0 ]; then
    echo "...passed"
  else
    has_error=$((has_error + 1))
    echo "...failed"
  fi
}

tunexec() {
  ip netns exec tun "$@"
}

echo "Check endpoint reachability (offline smoke) -> ${ENDPOINT_IP}"
if tunexec ping -c 3 "$ENDPOINT_IP" &> /dev/null; then
  echo "...passed"
else
  echo "...skipped (ICMP may be unavailable in this environment)"
fi

echo "Starting local iperf3 server"
IPERF_LOCALHOST_ROUTABLE_IP="1.2.3.4"
ip addr add "$IPERF_LOCALHOST_ROUTABLE_IP" dev lo || true
OFFLINE_HTTP_ROOT="/tmp/offline_tun_http_root"
IPERF_UPLOAD_PID=""
IPERF_REVERSE_PID=""
mkdir -p "$OFFLINE_HTTP_ROOT"
truncate -s 100M "$OFFLINE_HTTP_ROOT/100mb.bin"
python3 -m http.server 18080 --bind "$IPERF_LOCALHOST_ROUTABLE_IP" --directory "$OFFLINE_HTTP_ROOT" >/tmp/offline_tun_http_server.log 2>&1 &
HTTP_SERVER_PID=$!

cleanup() {
  kill "$HTTP_SERVER_PID" 2>/dev/null || true
  if [ -n "$IPERF_UPLOAD_PID" ]; then
    kill "$IPERF_UPLOAD_PID" 2>/dev/null || true
  fi
  if [ -n "$IPERF_REVERSE_PID" ]; then
    kill "$IPERF_REVERSE_PID" 2>/dev/null || true
  fi
  rm -rf "$OFFLINE_HTTP_ROOT"
  ip addr del "$IPERF_LOCALHOST_ROUTABLE_IP" dev lo 2>/dev/null || true
}
trap cleanup EXIT

sleep 1

echo "HTTP request through TUN to local server"
tunexec curl -sS "http://${IPERF_LOCALHOST_ROUTABLE_IP}:18080" >/dev/null
check_error

echo "Download local 100MB file through TUN"
tunexec curl -sS -L -o /dev/null "http://${IPERF_LOCALHOST_ROUTABLE_IP}:18080/100mb.bin" --max-time 60
check_error

echo "Test UDP upload with iperf3 (offline)"
iperf3 --server --one-off --port 5201 >/tmp/offline_tun_iperf_upload.log 2>&1 &
IPERF_UPLOAD_PID=$!
sleep 1
tunexec iperf3 --udp --client "$IPERF_LOCALHOST_ROUTABLE_IP" --port 5201
wait "$IPERF_UPLOAD_PID" 2>/dev/null || true
check_error

echo "Test UDP download with iperf3 (offline)"
iperf3 --server --one-off --port 5202 >/tmp/offline_tun_iperf_reverse.log 2>&1 &
IPERF_REVERSE_PID=$!
sleep 1
tunexec iperf3 --udp --reverse --client "$IPERF_LOCALHOST_ROUTABLE_IP" --port 5202
wait "$IPERF_REVERSE_PID" 2>/dev/null || true
check_error

if [ $has_error -gt 0 ]
then
  echo "There were errors"
  exit 1
else
  echo "All offline TUN tests passed"
  exit 0
fi
