# TrustTunnel Linux Platform Adapter

This directory provides the Linux daemon implementation (`trusttunneld`) for the TrustTunnel VPN client.
The daemon links the real TrustTunnel core (`vpnlibs_trusttunnel`) and is built as part of the
repository root project.

## Architecture

Unlike the Windows adapter (which relies on named pipes, helper installers, and complex C-API layers), the Linux implementation adheres to native Linux platform standards:

- IPC Protocol: [D-Bus](https://www.freedesktop.org/wiki/Software/dbus/) (`systemd/sd-bus`).
- Service Management: `systemd` (`Type=dbus`).
- Event Loop: `systemd/sd-event` for non-blocking single-threaded D-Bus IO.
- VPN Core: `ag::TrustTunnelClient` from `trusttunnel/`, driven on a dedicated thread
  (`AutoNetworkMonitor` + `set_system_dns()` + `connect()`), modelled after the CLI client.

The adapter is split into a client library and a thin daemon, following the same
methodology as the Windows adapter (library + service):

- `include/trusttunnel/trusttunnel.h` — the public C API of the client library
  (`trusttunnel_create` / `trusttunnel_start` / `trusttunnel_stop` / `trusttunnel_get_state`,
  an event fd + `trusttunnel_drain()` for event-loop integration, and event callbacks).
- `src/` — the static library (`trusttunnel_linux_a`, installed as `libtrusttunnel.a`):
  `VpnController` (owns the client lifecycle and bridges it to a single-threaded event
  loop) plus the thin C wrapper.
- `daemon/` — the `trusttunneld` executable: only sd-bus/sd-event glue mapping D-Bus
  methods to the library API and library callbacks to D-Bus signals.
  The D-Bus contract (`com.adguard.TrustTunnel.Vpn1`) is described in
  `daemon/resources/com.adguard.TrustTunnel.xml`.

The daemon needs `libsystemd`; the library itself does not.

### Threading model

`sd-bus` is not thread-safe, and the core invokes its callbacks from its own threads.
`VpnController` therefore owns an eventfd with a thread-safe message queue: the client callbacks
enqueue messages and write to the eventfd, and the daemon's event loop (`sd_event_add_io`) drains
the queue on the loop thread, where emitting D-Bus signals is safe.

The client lifecycle runs on a dedicated controller thread. `Stop` posts a stop request and returns
immediately; the thread performs a blocking `disconnect()` and publishes the final
`DISCONNECTED` state through the queue, so the event loop is never blocked.

## D-Bus Interface

- Bus Name: `com.adguard.TrustTunnel`
- Object Path: `/com/adguard/TrustTunnel`
- Interface: `com.adguard.TrustTunnel.Vpn1`

An XML introspection file is provided at `resources/com.adguard.TrustTunnel.xml`.

### Methods

- `Start(s toml_config) -> (u error_code)`: Start VPN with the TOML configuration
  (same format as the CLI client's `trusttunnel_client.toml`). Returns `VpnError`:
    - `0`: SUCCESS
    - `1`: ALREADY_RUNNING
    - `2`: INVALID_CONFIG
- `Stop() -> (u error_code)`: Stop VPN (returns `0` on success).
- `GetState() -> (i state)`: Query current state (`0=Disconnected`, `1=Connecting`, `2=Connected`, `3=WaitingRecovery`, `4=Recovering`, `5=WaitingForNetwork` — the values mirror the core's `ag::VpnSessionState`).
- `ClearLogs() -> ()`: Request daemon to clear its logs.

### Signals

- `StateChanged(i state)`: Emitted on every state transition.
- `ConnectionInfo(s json)`: Emitted with connection telemetry (JSON).
- `NetworkReady(s iface, s ipv4_address, u ipv4_prefix, s ipv6_address, u ipv6_prefix, u mtu, as dns_servers)`:
  Emitted once the tunnel device is initialized and its network parameters are final.

---

## Release artifacts

The archive contract for GUI clients (mirrors the Windows
`trusttunnel-client-windows-<version>-<arch>.zip`):

```text
trusttunnel-client-linux-<version>-<arch>/
├── bin/trusttunneld
├── lib/libtrusttunnel.a
├── lib/libtrusttunnel_deeplink_ffi.a
├── include/trusttunnel/trusttunnel.h
├── include/trusttunnel/trusttunnel_deeplink.h
├── lib/cmake/TrustTunnelClientLinux/TrustTunnelClientLinuxConfig.cmake
└── LICENSE
```

Both libraries are static (`-fPIC`, so they can be linked into shared objects), the
deeplink one carries its Rust standard-library system dependencies
(`pthread;dl;m`) through the imported `trusttunnel::deeplink` target.

Local assembly of the archive (the CI workflow calls the same scripts):

```bash
platform/linux/scripts/build.sh --version 1.3.0 [--arch x86_64|aarch64]
platform/linux/scripts/package.sh --staging-dir platform/linux/staging/trusttunnel-client-linux-<version>-<arch>
# -> platform/linux/artifacts/trusttunnel-client-linux-<version>-<arch>.zip
```

`build.sh` configures `platform/linux/` as a standalone project (the root is pulled in
automatically), so it works outside the root build too.

---

## Building

Prerequisites: `libsystemd-dev` (or `systemd-devel` on Fedora/RHEL). The daemon is built from the
repository root together with the core:

```bash
make build_linux_adapter
```

or by building the `trusttunneld` target in the root build directory directly. A standalone
`cmake -S platform/linux` configure works too (it pulls in the repository root, see the
release artifacts section above).

---

## Quick Testing with `busctl`

Two ways to drive the daemon manually, depending on what you want to check:

### D-Bus wiring only (no TUN)

Run unprivileged on the session bus — `Start()` accepts the config but fails at
TUN creation, because a regular user lacks `CAP_NET_ADMIN`. Useful to verify
methods, signals and state transitions only.

### Full run (TUN + routes): root on the system bus

A root process cannot connect to a *user* session bus (dbus-broker refuses
connections from a foreign UID), so `sudo ... --session` does not work. To
exercise the real path — TUN, routing, DNS — stop the installed service and
run the fresh binary on the system bus instead:

```bash
sudo systemctl stop trusttunneld
./cmake-build-clang-relwithdebinfo/platform/linux/trusttunneld --system
```

Drive it with `busctl --system` (see below), then restore the service with
`sudo systemctl start trusttunneld` when done.

### Terminal 1: Run Daemon

```bash
./cmake-build-clang-relwithdebinfo/platform/linux/trusttunneld --session
```

### Terminal 2: Monitor Signals

```bash
busctl --user monitor --match "interface='com.adguard.TrustTunnel.Vpn1'"
# ...or, for the system-bus run:
# busctl --system monitor --match "interface='com.adguard.TrustTunnel.Vpn1'"
```

### Terminal 3: Call Methods

```bash
# Substitute "--system" for "--user" when driving the system-bus run.

# Check initial state (returns 0 -> Disconnected)
busctl --user call com.adguard.TrustTunnel /com/adguard/TrustTunnel com.adguard.TrustTunnel.Vpn1 GetState

# Start VPN connection with a TOML configuration, e.g. one of the CLI client's configs:
CONFIG=$(cat trusttunnel_client.toml)
busctl --user call com.adguard.TrustTunnel /com/adguard/TrustTunnel com.adguard.TrustTunnel.Vpn1 Start s "$CONFIG"

# Watch the signals in Terminal 2 (Connecting -> NetworkReady -> Connected -> ConnectionInfo events)

# Stop VPN connection
busctl --user call com.adguard.TrustTunnel /com/adguard/TrustTunnel com.adguard.TrustTunnel.Vpn1 Stop
```
