#!/usr/bin/env bash
# Smoke test for trusttunneld on a private session bus.
#
# Starts the daemon under `dbus-run-session` and exercises the D-Bus API:
# GetState, Start with an invalid config (must answer INVALID_CONFIG), and Stop.
# Requires no privileges; the daemon fails later at TUN creation only if a
# valid configuration is used, so this keeps to the D-Bus wiring path.
#
# Usage: ./smoke_daemon.sh /path/to/trusttunneld

set -euo pipefail

BIN="${1:-}"
if [[ -z "$BIN" ]]; then
    echo "Usage: $0 /path/to/trusttunneld" >&2
    exit 2
fi
if [[ ! -x "$BIN" ]]; then
    echo "Error: not an executable: $BIN" >&2
    exit 2
fi
for tool in busctl dbus-run-session; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: $tool is required" >&2
        exit 1
    fi
done

export TRUSTTUNNELD_BIN="$BIN"
status=0
dbus-run-session -- bash <<'INNER' || status=$?
    set -u
    bus="busctl --user call com.adguard.TrustTunnel /com/adguard/TrustTunnel com.adguard.TrustTunnel.Vpn1"

    "$TRUSTTUNNELD_BIN" --session &
    pid=$!
    cleanup() {
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    }
    trap cleanup EXIT

    ready=0
    for _ in $(seq 1 50); do
        if $bus GetState >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [[ "$ready" != 1 ]]; then
        echo "trusttunneld did not acquire the bus name" >&2
        exit 1
    fi

    state=$($bus GetState | awk '{print $2}')
    if [[ "$state" != 0 ]]; then
        echo "GetState returned '$state', expected 0" >&2
        exit 1
    fi

    invalid=$($bus Start s 'this is [[ not toml' | awk '{print $2}')
    if [[ "$invalid" != 2 ]]; then
        echo "Start with an invalid config returned '$invalid', expected 2 (INVALID_CONFIG)" >&2
        exit 1
    fi

    # busctl needs the explicit input signature when a method has more than one argument
    invalid_ex=$($bus StartEx sb 'this is [[ not toml' false | awk '{print $2}')
    if [[ "$invalid_ex" != 2 ]]; then
        echo "StartEx with an invalid config returned '$invalid_ex', expected 2 (INVALID_CONFIG)" >&2
        exit 1
    fi

    stopped=$($bus Stop | awk '{print $2}')
    if [[ "$stopped" != 0 ]]; then
        echo "Stop returned '$stopped', expected 0" >&2
        exit 1
    fi

    cleanup
    trap - EXIT
INNER

if [[ "$status" -eq 0 ]]; then
    echo "smoke test passed"
else
    echo "smoke test failed" >&2
fi
exit "$status"
