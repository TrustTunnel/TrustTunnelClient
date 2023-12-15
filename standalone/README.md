# AdGuard Standalone VPN Client

[![AdGuardVPN.com](https://img.shields.io/badge/AdGuardVPN.com-Visit-007BFF)](https://adguard-vpn.com/)

AdGuard Standalone VPN Client is an application built on top of the AdGuard VPN Libraries.
It provides an easy-to-use interface to configure and connect to an AdGuard VPN endpoint.
The client supports Linux, macOS, and Windows platforms.

---

## Building

To build the AdGuard Standalone VPN Client, follow [these steps](../README.md#build-instructions)
The built executable will be available in the `<project_root>/build/standalone_client` directory.

---

## Configuration

The AdGuard Standalone VPN Client accepts a TOML-formatted configuration file.
You can use the setup wizard tool to generate a basic configuration file.

### Setup Wizard Tool

#### Usage

For quick setup, please follow [here](../README.md#quick-start-the-standalone-vpn-client).

For a more customized configuration experience, follow the steps below:

1. [Build](../README.md#building) the setup wizard tool.

2. Launch the setup wizard:

   ```shell
   ./setup_wizard
   ```

   The setup wizard will guide you through the configuration process, allowing you to customize the
   settings according to your preferences.

> Note: The configuration file created by the setup wizard contains all available settings,
> including descriptions. Feel free to modify them if you have a good understanding of the
> configuration.

---

## Usage

To run the AdGuard Standalone VPN Client, execute the following command:

```shell
./standalone_client --config <path/to/configuration/file.toml>
```

Replace `<path/to/configuration/file.toml>` with the actual path to your configuration file.
You may need to run the command with superuser privileges if a TUN device is selected.
