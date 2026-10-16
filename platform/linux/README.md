# TrustTunnel Linux Platform Adapter

This directory provides the Linux daemon implementation (`trusttunneld`) for the TrustTunnel VPN client.

## Architecture

Unlike the Windows adapter (which relies on named pipes, helper installers, and complex C-API layers), the Linux implementation adheres to native Linux platform standards:
- IPC Protocol: [D-Bus](https://www.freedesktop.org/wiki/Software/dbus/) (`systemd/sd-bus`).
- Service Management: `systemd` (`Type=dbus` or `Type=notify`).
- Event Loop: `systemd/sd-event` for non-blocking single-threaded D-Bus IO and timer scheduling.

## D-Bus Interface

- Bus Name: `com.adguard.TrustTunnel`
- Object Path: `/com/adguard/TrustTunnel`
- Interface: `com.adguard.TrustTunnel.Vpn1`

An XML introspection file is provided at `resources/com.adguard.TrustTunnel.xml`.

### Methods
- `Start(s toml_config) -> (u error_code)`: Start VPN with configuration. Returns `VpnError`:
  - `0`: SUCCESS
  - `1`: ALREADY_RUNNING
  - `2`: INVALID_CONFIG
  *(Note: Unlike the legacy Windows-pipe error codes, Linux D-Bus uses minimal, explicit enum values)*
- `Stop() -> (u error_code)`: Stop VPN (returns `0` on success).
- `GetState() -> (i state)`: Query current state (`0=Disconnected`, `1=Connecting`, `2=Connected`, `3=WaitingRecovery`, `4=Recovering`, `5=WaitingForNetwork`).
- `ClearLogs() -> ()`: Request daemon to clear its logs.

### Signals
- `StateChanged(i state)`: Emitted on every state transition.
- `ConnectionInfo(s json)`: Emitted with connection/traffic telemetry.

---

## Building

Prerequisites: `libsystemd-dev` (or `systemd-devel` on Fedora/RHEL).

```bash
cmake -S platform/linux -B build-linux -G Ninja
ninja -C build-linux
```

---

## Quick Testing with `busctl`

You can test the daemon directly without needing root privileges by running on the user/session bus:

### Terminal 1: Run Daemon
```bash
./build-linux/trusttunneld --session
```

### Terminal 2: Monitor Signals
```bash
busctl --user monitor --match "interface='com.adguard.TrustTunnel.Vpn1'"
```

### Terminal 3: Call Methods
```bash
# Check initial state (returns 0 -> Disconnected)
busctl --user call com.adguard.TrustTunnel /com/adguard/TrustTunnel com.adguard.TrustTunnel.Vpn1 GetState

# Start VPN connection
busctl --user call com.adguard.TrustTunnel /com/adguard/TrustTunnel com.adguard.TrustTunnel.Vpn1 Start s "[endpoint]"

# Watch the signals in Terminal 2 (Connecting -> Connected -> ConnectionInfo events)

# Stop VPN connection
busctl --user call com.adguard.TrustTunnel /com/adguard/TrustTunnel com.adguard.TrustTunnel.Vpn1 Stop
```
