# <p align="center">TrustTunnel CLI Client</p>
<p align="center">Simple, fast and secure CLI client for the TrustTunnel VPN</p>

TrustTunnel CLI Client is an application built on top of the TrustTunnel Client Libraries.
It provides an easy-to-use interface to configure and connect to an TrustTunnel endpoint.
The client supports Linux, macOS, and Windows platforms.

---

## Building

To build the TrustTunnel CLI Client, follow [these steps](../README.md#build-instructions)
The built executable will be available in the `<project_root>/build/trusttunnel_client` directory.

---

## Configuration

The TrustTunnel CLI Client accepts a TOML-formatted configuration file.
You can use the setup wizard tool to generate a basic configuration file.

### Setup Wizard Tool

#### Usage

For quick setup, please follow [here](../README.md#quick-start-the-trusttunnel-vpn-client).

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

To run the TrustTunnel CLI Client, execute the following command:

```shell
./trusttunnel_client --config <path/to/configuration/file.toml>
```

Replace `<path/to/configuration/file.toml>` with the actual path to your configuration file.
You may need to run the command with superuser privileges if a TUN device is selected.
