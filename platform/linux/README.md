# TrustTunnel Linux Adapter

Easy wrapper for the TrustTunnel VPN API on Linux: a static C library with two operations,
`start` (takes a TOML configuration) and `stop`, mirroring the
[Windows adapter](../windows/README.md).

The library owns the VPN client lifecycle (modelled after the CLI client) and reports events
through callbacks:

```c
trusttunnel_start(toml_config, /*fall_into_recovery=*/false, on_state_changed, arg);
trusttunnel_stop();
```

For an in-process instance use the explicit form:

```c
trusttunnel_t *vpn = trusttunnel_start_ex(toml_config, false, on_state_changed, arg,
                                          on_connection_info, info_arg);
if (vpn == NULL) {
    /* invalid configuration or the client could not be created */
}
trusttunnel_stop_ex(vpn);
```

Callbacks are invoked from the library's internal threads. Do not run non-trivial work inside
them and do not call the library's functions without a context switch.

## Runtime requirements

- `/dev/net/tun` access and `CAP_NET_ADMIN` to create and configure the tunnel device;
- the TOML configuration is the same as the CLI client's (`trusttunnel_client.toml`).

## Building

```sh
cmake -S . -B cmake-build-relwithdebinfo -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build cmake-build-relwithdebinfo --target trusttunnel_linux
```

Tests live in `test/` and run through `ctest`. Test binaries are excluded from the default build
(`EXCLUDE_FROM_ALL`), so build the `tests` target explicitly before running them:

```sh
cmake --build cmake-build-relwithdebinfo --target tests
ctest --test-dir cmake-build-relwithdebinfo -R 'TrusttunnelCapiTest|VpnControllerTest'
```

## Consuming the installed package

```cmake
find_package(TrustTunnelClientLinux REQUIRED)
target_link_libraries(myapp PRIVATE TrustTunnelClientLinux::trusttunnel)
```

The package installs `libtrusttunnel.a`, `include/trusttunnel/trusttunnel.h`, and a generated
`TrustTunnelClientLinuxConfig.cmake` under the CMake config directory for the target library
directory (`lib/cmake/...`, or `lib64/cmake/...` on distributions that default to `lib64`).

The library is static because its Conan dependencies are built without `-fPIC`; link it into
your executable or shared object and provide those transitive dependencies (Thread, libevent,
nghttp2, dns-libs, OpenSSL, and so on).
