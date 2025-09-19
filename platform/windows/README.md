# Easy wrapper for AdGuard VPI API
- Basically, the `standalone_client` command line application in the form of a library.
- Only two buttons: `start` and `stop`. The first one accepts the configuration in TOML format.
- For tunnel listener to work, `wintun.dll` (architecture matching the `vpn_easy` binary)
  must be in the DLL search path.
- For tunnel listener to work, the process must have administrator privileges.
