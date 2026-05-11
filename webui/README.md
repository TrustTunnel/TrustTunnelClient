# TrustTunnel WebUI

A local web interface for managing [TrustTunnelClient](https://github.com/TrustTunnel/TrustTunnelClient) on macOS — replaces manual TOML editing with a browser UI.

## Stack

- **Backend**: Go — reads/writes `trusttunnel_client.toml`, manages the client process, streams logs over SSE
- **Frontend**: React 19 + Tailwind CSS v4 + Zustand — dark-theme SPA embedded in the Go binary
- **Build**: esbuild (Go binary) + PostCSS API — no native Node bindings needed at runtime

## Features

| Page | Description |
|------|-------------|
| Dashboard | Connection status, external IP, uptime, connect/disconnect |
| Config | Visual editor for the full TOML config |
| Exclusions | Manage split-tunnel exclusion rules |
| DNS | Configure DNS upstreams (plain/DoT/DoH/DoQ/stamp) |
| Logs | Real-time log stream from the client process (SSE) |

## Prerequisites

- Go ≥ 1.23
- Node.js (Homebrew: `/opt/homebrew/bin/node`)
- `trusttunnel_client` binary and `trusttunnel_client.toml` (see upstream repo)

## Quick start

```bash
cd webui

# 1. Install npm dependencies
make setup

# 2. Fix macOS 25 native-binding Team ID issue (one-time)
make node-unlock

# 3. Build frontend + Go binary
make build

# 4. Run (requires sudo for TUN mode)
sudo ./trusttunnel-webui

# Open http://127.0.0.1:7878
```

## CLI flags

```
--client  path to trusttunnel_client binary  (default: ~/Applications/trusttunnel_client/trusttunnel_client)
--config  path to trusttunnel_client.toml    (default: ~/Applications/trusttunnel_client/trusttunnel_client.toml)
--addr    WebUI listen address               (default: 127.0.0.1:7878)
```

Example:
```bash
sudo ./trusttunnel-webui \
  --client /usr/local/bin/trusttunnel_client \
  --config /etc/trusttunnel/config.toml \
  --addr 0.0.0.0:7878
```

## macOS note

`trusttunnel_client` requires elevated privileges to create a TUN interface. Run the WebUI daemon with `sudo` or via a LaunchDaemon plist.

The build step uses a local ad-hoc-signed copy of node (`make node-unlock`) to bypass a macOS 25 security enforcement that blocks native Node.js bindings (rolldown, lightningcss) from loading when signed by a different Team ID than the node binary.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Process status, external IP, interface, uptime |
| GET | `/api/config` | Current config as JSON |
| PUT | `/api/config` | Save updated config |
| POST | `/api/connect` | Start `trusttunnel_client` |
| POST | `/api/disconnect` | Stop `trusttunnel_client` |
| GET | `/api/logs` | SSE stream of stdout/stderr |
