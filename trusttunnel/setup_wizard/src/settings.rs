pub use trusttunnel_settings::Endpoint;

use crate::user_interaction::{
    ask_for_agreement, ask_for_agreement_with_default, ask_for_input, ask_for_password,
    select_variant,
};
use crate::Mode;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::ops::Not;
use x509_parser::extensions::GeneralName;

macro_rules! docgen {
    (
        $(#{doc($($args1:tt)*)})?
        $(#[$meta1:meta])*
        $vis1:vis struct $Struct:ident {
            $(
                $(#{doc($($args2:tt)*)})?
                $(#[$meta2:meta])*
                $vis2:vis $field:ident: $ty:ty,
            )*
        }
    ) => {
        $(#[doc = $($args1)*])?
        $(#[$meta1])*
        $vis1 struct $Struct {
            $(
                $(#[doc = $($args2)*])?
                $(#[$meta2])*
                $vis2 $field: $ty,
            )*
        }

        impl $Struct {
            $(
                pub fn doc() -> &'static str {
                    std::concat!($($args1)*).into()
                }
            )?

            paste::paste! {
                $(
                    $(
                        pub fn [<doc_ $field>]() -> &'static str {
                            std::concat!($($args2)*).into()
                        }
                    )?
                )*
            }
        }
    };
}

docgen! {
    #[derive(Deserialize, Serialize)]
    pub struct Settings {
        #{doc("Logging level [info, debug, trace]")}
        #[serde(default = "Settings::default_loglevel")]
        pub loglevel: String,
        #{doc(r#"VPN mode.
Defines client connections routing policy:
* general: route through a VPN endpoint all connections except ones which destinations are in exclusions,
* selective: route through a VPN endpoint only the connections which destinations are in exclusions."#)}
        #[serde(default = "Settings::default_vpn_mode")]
        pub vpn_mode: String,
        #{doc(r#"When disabled, all connection requests are routed directly to target hosts
in case connection to VPN endpoint is lost. This helps not to break an
Internet connection if user has poor connectivity to an endpoint.
When enabled, incoming connection requests which should be routed through
an endpoint will not be routed directly in that case."#)}
        #[serde(default = "Settings::default_killswitch_enabled")]
        pub killswitch_enabled: bool,
        #{doc(r#"When the kill switch is enabled, on platforms where inbound connections are blocked by the
kill switch, allow inbound connections to these local ports. An array of integers."#)}
        #[serde(default = "Settings::default_killswitch_allow_ports")]
        pub killswitch_allow_ports: Vec<u16>,
        #{doc(r#"When enabled, a post-quantum group may be used for key exchange
in TLS handshakes initiated by the VPN client."#)}
        #[serde(default = "Settings::default_post_quantum_group_enabled")]
        pub post_quantum_group_enabled: bool,
        #{doc(r#"Domains and addresses which should be routed in a special manner.
Supported syntax:
  * domain name
    * if starts with "*.", any subdomain of the domain will be matched including
      www-subdomain, but not the domain itself (e.g., `*.example.com` will match
      `sub.example.com`, `sub.sub.example.com`, `www.example.com`, but not `example.com`)
    * if starts with "www." or it's just a domain name, the domain itself and its
      www-subdomain will be matched (e.g. `example.com` and `www.example.com` will
      match `example.com` `www.example.com`, but not `sub.example.com`)
  * ip address
    * recognized formats are:
      * [IPv6Address]:port
      * [IPv6Address]
      * IPv6Address
      * IPv4Address:port
      * IPv4Address
    * if port is not specified, any port will be matched
  * CIDR range
    * recognized formats are:
      * IPv4Address/mask
      * IPv6Address/mask"#)}
        #[serde(default)]
        pub exclusions: Vec<String>,
        #{doc(r#"DNS upstreams.
If specified, the library intercepts and routes plain DNS queries
going through the endpoint to the DNS resolvers.
One of the following kinds:
  * 8.8.8.8:53 -- plain DNS
  * tcp://8.8.8.8:53 -- plain DNS over TCP
  * tls://1.1.1.1 -- DNS-over-TLS
  * https://dns.adguard.com/dns-query -- DNS-over-HTTPS
  * sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
  * quic://dns.adguard.com:8853 -- DNS-over-QUIC"#)}
        #[serde(default)]
        pub dns_upstreams: Vec<String>,
        pub endpoint: Endpoint,
        #[serde(default)]
        pub listener: Listener,
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Listener {
    Socks(SocksListener),
    Tun(TunListener),
}

impl Default for Listener {
    fn default() -> Self {
        Self::Socks(Default::default())
    }
}

docgen! {
    #[derive(Default, Deserialize, Serialize)]
    pub struct SocksListener {
        #{doc("IP address to bind the listener to")}
        #[serde(default = "SocksListener::default_address")]
        pub address: String,
        #{doc("Username for authentication if desired")}
        pub username: Option<String>,
        #{doc("Password for authentication if desired")}
        pub password: Option<String>,
    }
}

docgen! {
    #[derive(Deserialize, Serialize)]
    pub struct TunListener {
        #{doc(r#"Name of the interface used for connections made by the VPN client.
On Linux, Windows and macOS, it is detected automatically if not specified.
On Windows, an interface index as shown by `route print`, written as a string, may be used instead of a name."#)}
        #[serde(default = "TunListener::default_bound_if")]
        pub bound_if: String,
        #{doc("Routes in CIDR notation to set to the virtual interface")}
        #[serde(default = "TunListener::default_included_routes")]
        pub included_routes: Vec<String>,
        #{doc("Routes in CIDR notation to exclude from routing through the virtual interface")}
        #[serde(default = "TunListener::default_excluded_routes")]
        pub excluded_routes: Vec<String>,
        #{doc("MTU size on the interface")}
        #[serde(default = "TunListener::default_mtu_size")]
        pub mtu_size: usize,
        #{doc("Allow changing system DNS servers")}
        #[serde(default = "TunListener::default_change_system_dns")]
        pub change_system_dns: bool,
    }
}

impl Settings {
    pub fn default_loglevel() -> String {
        "info".into()
    }

    fn available_vpn_modes() -> &'static [&'static str] {
        &["general", "selective"]
    }

    pub fn default_vpn_mode() -> String {
        "general".into()
    }

    pub fn default_killswitch_enabled() -> bool {
        true
    }

    pub fn default_killswitch_allow_ports() -> Vec<u16> {
        Vec::new()
    }

    pub fn default_post_quantum_group_enabled() -> bool {
        // Keep in sync with common/include/vpn/default_settings.h
        // VPN_DEFAULT_POST_QUANTUM_GROUP_ENABLED
        true
    }
}

impl Listener {
    pub fn default_kind() -> String {
        "tun".into()
    }

    fn available_kinds() -> &'static [&'static str] {
        &["socks", "tun"]
    }

    pub fn to_kind_string(&self) -> String {
        match self {
            Listener::Socks(_) => "socks",
            Listener::Tun(_) => "tun",
        }
        .into()
    }
}

impl SocksListener {
    pub fn default_address() -> String {
        "127.0.0.1:1080".into()
    }
}

impl TunListener {
    pub fn default_bound_if() -> String {
        "".into()
    }

    pub fn default_included_routes() -> Vec<String> {
        vec!["0.0.0.0/0".into(), "2000::/3".into()]
    }

    pub fn default_excluded_routes() -> Vec<String> {
        vec![
            "0.0.0.0/8".into(),
            "10.0.0.0/8".into(),
            "169.254.0.0/16".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
            "224.0.0.0/3".into(),
        ]
    }
    pub fn default_mtu_size() -> usize {
        1280
    }

    pub fn default_change_system_dns() -> bool {
        true
    }
}

macro_rules! opt_field {
    ($x:expr, $field:ident) => {
        $x.map(|x| &x.$field)
    };
}

pub fn build(template: Option<&Settings>) -> Settings {
    Settings {
        loglevel: opt_field!(template, loglevel)
            .cloned()
            .unwrap_or_else(Settings::default_loglevel),
        vpn_mode: select_variant(
            format!("{}\n", Settings::doc_vpn_mode()),
            Settings::available_vpn_modes(),
            Settings::available_vpn_modes().iter().position(|x| {
                *x == opt_field!(template, vpn_mode)
                    .cloned()
                    .unwrap_or_else(Settings::default_vpn_mode)
                    .as_str()
            }),
        )
        .into(),
        killswitch_enabled: opt_field!(template, killswitch_enabled)
            .cloned()
            .unwrap_or_else(Settings::default_killswitch_enabled),
        killswitch_allow_ports: opt_field!(template, killswitch_allow_ports)
            .cloned()
            .unwrap_or_else(Settings::default_killswitch_allow_ports),
        post_quantum_group_enabled: opt_field!(template, post_quantum_group_enabled)
            .cloned()
            .unwrap_or_else(Settings::default_post_quantum_group_enabled),
        exclusions: opt_field!(template, exclusions)
            .cloned()
            .unwrap_or_default(),
        dns_upstreams: opt_field!(template, dns_upstreams)
            .cloned()
            .unwrap_or_default(),
        endpoint: build_endpoint(opt_field!(template, endpoint)),
        listener: build_listener(opt_field!(template, listener)),
    }
}

fn build_endpoint(template: Option<&Endpoint>) -> Endpoint {
    let predefined_params = crate::get_predefined_params().clone();

    // Deep-link import: if provided via CLI, decode and return immediately
    if let Some(ref deeplink_uri) = predefined_params.deeplink {
        return endpoint_from_deeplink(deeplink_uri);
    }

    // In interactive mode, offer a choice between config file and deep-link
    let endpoint_config: Option<EndpointConfig> =
        if crate::get_mode() == Mode::Interactive && predefined_params.endpoint_config.is_none() {
            let selection = crate::user_interaction::select_index(
                "How would you like to provide endpoint configuration?",
                &["Endpoint config file", "Deep-link URI (tt://...)"],
                Some(0),
            );
            match selection {
                0 => {
                    // Endpoint config file path
                    empty_to_none(ask_for_input(
                        "Path to endpoint config, empty if no",
                        Some("".to_string()),
                    ))
                    .and_then(|x| {
                        fs::read_to_string(&x)
                            .map_err(|e| panic!("Failed to read endpoint config file:\n{}", e))
                            .ok()
                    })
                    .and_then(|x| {
                        toml::de::from_str(x.as_str())
                            .map_err(|e| panic!("Failed to parse endpoint config:\n{}", e))
                            .ok()
                    })
                }
                1 => {
                    // Deep-link URI
                    let uri = ask_for_input::<String>("Paste deep-link URI", None);
                    return endpoint_from_deeplink(&uri);
                }
                _ => unreachable!(),
            }
        } else {
            empty_to_none(ask_for_input(
                "Path to endpoint config, empty if no",
                predefined_params.endpoint_config.or(Some("".to_string())),
            ))
            .and_then(|x| {
                fs::read_to_string(&x)
                    .map_err(|e| panic!("Failed to read endpoint config file:\n{}", e))
                    .ok()
            })
            .and_then(|x| {
                toml::de::from_str(x.as_str())
                    .map_err(|e| panic!("Failed to parse endpoint config:\n{}", e))
                    .ok()
            })
        };
    let mut x = Endpoint {
        addresses: endpoint_config
            .as_ref()
            .and_then(|x| x.addresses.clone().into())
            .or_else(|| {
                ask_for_input::<String>(
                    &format!(
                        "{}\nMust be delimited by whitespace.\n",
                        Endpoint::doc_addresses()
                    ),
                    predefined_params
                        .endpoint_addresses
                        .or(opt_field!(template, addresses).cloned())
                        .map(|x| x.join(" ")),
                )
                .split_whitespace()
                .map(String::from)
                .collect::<Vec<String>>()
                .into()
            })
            .unwrap(),
        has_ipv6: endpoint_config
            .as_ref()
            .and_then(|x| x.has_ipv6.into())
            .or(opt_field!(template, has_ipv6).cloned())
            .unwrap_or_else(Endpoint::default_has_ipv6),
        username: endpoint_config
            .as_ref()
            .and_then(|x| x.username.clone().into())
            .or_else(|| {
                ask_for_input(
                    Endpoint::doc_username(),
                    predefined_params
                        .credentials
                        .clone()
                        .unzip()
                        .0
                        .or(opt_field!(template, username).cloned()),
                )
                .into()
            })
            .unwrap(),
        password: endpoint_config
            .as_ref()
            .and_then(|x| x.password.clone().into())
            .or_else(|| {
                predefined_params
                    .credentials
                    .unzip()
                    .1
                    .unwrap_or_else(|| {
                        opt_field!(template, password)
                            .cloned()
                            .and_then(empty_to_none)
                            .and_then(|x| {
                                ask_for_agreement("Overwrite password?").not().then_some(x)
                            })
                            .unwrap_or_else(|| ask_for_password(Endpoint::doc_password()))
                    })
                    .into()
            })
            .unwrap(),
        client_random: endpoint_config
            .as_ref()
            .and_then(|x| x.client_random.clone().into())
            .or(opt_field!(template, client_random).cloned())
            .unwrap_or_default(),
        skip_verification: endpoint_config
            .as_ref()
            .and_then(|x| x.skip_verification.into())
            .or(opt_field!(template, skip_verification).cloned())
            .unwrap_or_else(Endpoint::default_skip_verification),
        upstream_protocol: endpoint_config
            .as_ref()
            .and_then(|x| x.upstream_protocol.clone().into())
            .or(opt_field!(template, upstream_protocol).cloned())
            .unwrap_or_else(Endpoint::default_upstream_protocol),
        anti_dpi: endpoint_config
            .as_ref()
            .and_then(|x| x.anti_dpi.into())
            .or(opt_field!(template, anti_dpi).cloned())
            .unwrap_or_else(Endpoint::default_anti_dpi),
        custom_sni: endpoint_config
            .as_ref()
            .and_then(|x| empty_to_none(x.custom_sni.clone()))
            .unwrap_or_default(),
        ..Default::default()
    };

    if endpoint_config.is_some() {
        let config = endpoint_config.as_ref().unwrap();
        x.hostname = config.hostname.clone();
        x.certificate = config.certificate.clone().into();
    } else {
        let (hostname, certificate) = if crate::get_mode() == Mode::NonInteractive {
            (
                predefined_params.hostname.clone(),
                predefined_params.certificate.and_then(|x| {
                    fs::read_to_string(&x)
                        .expect("Failed to read certificate")
                        .into()
                }),
            )
        } else if let Some(cert) = opt_field!(template, certificate)
            .cloned()
            .flatten()
            .and_then(parse_cert)
            .and_then(|x| {
                ask_for_agreement(&format!("Use an existent certificate? {:?}", x)).then_some(x)
            })
        {
            (
                Some(cert.common_name),
                opt_field!(template, certificate).cloned().flatten(),
            )
        } else if let Some(cert) = empty_to_none(ask_for_input::<String>(
            &format!(
                "{}\nEnter a path to certificate:",
                Endpoint::doc_certificate()
            ),
            Some("".into()),
        )) {
            let contents = fs::read_to_string(&cert).expect("Failed to read certificate");
            match parse_cert(contents.clone()) {
                Some(parsed) => (Some(parsed.common_name), Some(contents)),
                None => {
                    panic!("Couldn't parse provided certificate");
                }
            }
        } else {
            (None, None)
        };

        x.hostname = ask_for_input(
            Endpoint::doc_hostname(),
            predefined_params
                .hostname
                .or(opt_field!(template, hostname).cloned())
                .or(hostname),
        );
        x.custom_sni = empty_to_none(ask_for_input(
            &format!("{}\nLeave empty if not needed.", Endpoint::doc_custom_sni()),
            predefined_params
                .custom_sni
                .or(opt_field!(template, custom_sni).cloned())
                .or(Some("".to_string())),
        ))
        .unwrap_or_default();
        x.certificate = certificate;
    }

    if x.certificate.is_some() {
        parse_cert(x.certificate.clone().unwrap()).expect("Couldn't parse provided certificate");
    }

    x.skip_verification = x.certificate.is_none()
        && ask_for_agreement_with_default(
            &format!("{}\n", Endpoint::doc_skip_verification()),
            opt_field!(template, skip_verification)
                .cloned()
                .unwrap_or_default(),
        );

    x
}

fn build_listener(template: Option<&Listener>) -> Listener {
    match select_variant(
        r#"Listener type:
    * socks: SOCKS5 proxy with UDP support,
    * tun: TUN device.
"#,
        Listener::available_kinds(),
        Listener::available_kinds().iter().position(|x| {
            *x == template
                .map(Listener::to_kind_string)
                .unwrap_or_else(Listener::default_kind)
                .as_str()
        }),
    ) {
        "socks" => {
            let template = template.and_then(|x| match x {
                Listener::Socks(x) => Some(x),
                _ => None,
            });
            Listener::Socks(SocksListener {
                address: ask_for_input(
                    SocksListener::doc_address(),
                    Some(
                        opt_field!(template, address)
                            .cloned()
                            .unwrap_or_else(SocksListener::default_address),
                    ),
                ),
                username: empty_to_none(ask_for_input(
                    SocksListener::doc_username(),
                    Some(
                        opt_field!(template, username)
                            .cloned()
                            .flatten()
                            .unwrap_or_default(),
                    ),
                )),
                password: empty_to_none(ask_for_input(
                    SocksListener::doc_password(),
                    Some(
                        opt_field!(template, password)
                            .cloned()
                            .flatten()
                            .unwrap_or_default(),
                    ),
                )),
            })
        }
        "tun" => {
            let template = template.and_then(|x| match x {
                Listener::Tun(x) => Some(x),
                _ => None,
            });
            Listener::Tun(TunListener {
                bound_if: if cfg!(target_os = "windows") {
                    Default::default()
                } else {
                    ask_for_input(
                        TunListener::doc_bound_if(),
                        Some(
                            opt_field!(template, bound_if)
                                .cloned()
                                .unwrap_or_else(TunListener::default_bound_if),
                        ),
                    )
                },
                included_routes: opt_field!(template, included_routes)
                    .cloned()
                    .unwrap_or_else(TunListener::default_included_routes),
                excluded_routes: opt_field!(template, excluded_routes)
                    .cloned()
                    .unwrap_or_else(TunListener::default_excluded_routes),
                mtu_size: opt_field!(template, mtu_size)
                    .cloned()
                    .unwrap_or_else(TunListener::default_mtu_size),
                change_system_dns: ask_for_agreement_with_default(
                    &format!("{}\n", TunListener::doc_change_system_dns()),
                    opt_field!(template, change_system_dns)
                        .cloned()
                        .unwrap_or_else(TunListener::default_change_system_dns),
                ),
            })
        }
        _ => unreachable!(),
    }
}

fn empty_to_none(str: String) -> Option<String> {
    str.is_empty().not().then_some(str)
}

#[derive(Deserialize, Debug)]
pub struct EndpointConfig {
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    has_ipv6: bool,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    client_random: String,
    #[serde(default)]
    skip_verification: bool,
    #[serde(default)]
    certificate: String,
    #[serde(default)]
    upstream_protocol: String,
    #[serde(default)]
    anti_dpi: bool,
    #[serde(default)]
    custom_sni: String,
}

#[derive(Debug)]
struct Cert {
    common_name: String,
    #[allow(dead_code)] // needed only for logging
    alt_names: Vec<String>,
    #[allow(dead_code)] // needed only for logging
    expiration_date: String,
}

fn parse_cert(contents: String) -> Option<Cert> {
    let cert = rustls_pemfile::certs(&mut contents.as_bytes())
        .ok()?
        .into_iter()
        .map(rustls::Certificate)
        .next()?;
    let cert = x509_parser::parse_x509_certificate(&cert.0).ok()?.1;
    Some(Cert {
        common_name: cert.validity.is_valid().then(|| {
            let x = cert.subject.to_string();
            x.as_str()
                .strip_prefix("CN=")
                .map(String::from)
                .unwrap_or(x)
        })?,
        alt_names: cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|x| {
                x.value
                    .general_names
                    .iter()
                    .map(GeneralName::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        expiration_date: cert.validity.not_after.to_string(),
    })
}

#[derive(Debug)]
pub struct CertInfo {
    pub common_name: String,
    pub expiration_date: String,
}

/// Helper struct for pretty-printing Endpoint
pub struct EndpointSummary<'a> {
    endpoint: &'a Endpoint,
    cert_infos: &'a [CertInfo],
}

impl<'a> EndpointSummary<'a> {
    pub fn new(endpoint: &'a Endpoint, cert_infos: &'a [CertInfo]) -> Self {
        Self {
            endpoint,
            cert_infos,
        }
    }
}

impl fmt::Display for EndpointSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ep = self.endpoint;

        let addresses = ep.addresses.join(", ");
        let custom_sni = if ep.custom_sni.is_empty() {
            "(none)"
        } else {
            &ep.custom_sni
        };
        let client_random = if ep.client_random.is_empty() {
            "(none)"
        } else {
            &ep.client_random
        };

        let cert_display = if self.cert_infos.is_empty() {
            if ep.certificate.is_some() {
                "(present)".to_string()
            } else {
                "(none)".to_string()
            }
        } else {
            self.cert_infos
                .iter()
                .map(|c| format!("CN={} (expires {})", c.common_name, c.expiration_date))
                .collect::<Vec<_>>()
                .join("\n                     ")
        };

        write!(
            f,
            "
  Hostname:          {}
  Addresses:         {}
  Custom SNI:        {}
  IPv6:              {}
  Username:          {}
  Password:          ******
  Client random:     {}
  Skip verification: {}
  Certificate:       {}
  Protocol:          {}
  Anti-DPI:          {}",
            ep.hostname,
            addresses,
            custom_sni,
            if ep.has_ipv6 { "yes" } else { "no" },
            ep.username,
            client_random,
            if ep.skip_verification { "yes" } else { "no" },
            cert_display,
            ep.upstream_protocol,
            if ep.anti_dpi { "yes" } else { "no" },
        )
    }
}

fn verify_deeplink_certificates(der_bytes: &[u8]) -> Vec<CertInfo> {
    let pem = trusttunnel_deeplink::cert::der_to_pem(der_bytes)
        .expect("Failed to convert deep-link certificate from DER to PEM");

    let certs = rustls_pemfile::certs(&mut pem.as_bytes())
        .expect("Failed to parse PEM certificates from deep-link");

    if certs.is_empty() {
        panic!("Deep-link certificate field contains no valid certificates");
    }

    let mut cert_infos = Vec::new();
    for (i, cert_der) in certs.iter().enumerate() {
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref())
            .unwrap_or_else(|e| panic!("Failed to parse certificate #{}: {}", i + 1, e));

        if !cert.validity.is_valid() {
            panic!(
                "Certificate #{} (CN={}) is not valid: not_before={}, not_after={}",
                i + 1,
                cert.subject,
                cert.validity.not_before,
                cert.validity.not_after
            );
        }

        let cn = {
            let subj = cert.subject.to_string();
            subj.strip_prefix("CN=").map(String::from).unwrap_or(subj)
        };

        cert_infos.push(CertInfo {
            common_name: cn,
            expiration_date: cert.validity.not_after.to_string(),
        });
    }

    cert_infos
}

fn display_and_confirm_endpoint(endpoint: &Endpoint, cert_infos: &[CertInfo]) {
    println!("{}\n", EndpointSummary::new(endpoint, cert_infos));

    if crate::get_mode() == Mode::Interactive
        && !ask_for_agreement_with_default("Accept this configuration?", false)
    {
        eprintln!("Deep-link configuration declined by user.");
        std::process::exit(1);
    }
}

pub fn endpoint_from_deeplink(uri: &str) -> Endpoint {
    let config = trusttunnel_deeplink::decode(uri)
        .unwrap_or_else(|e| panic!("Failed to decode deep-link URI: {}", e));

    let cert_infos = config
        .certificate
        .as_ref()
        .map(|der| verify_deeplink_certificates(der))
        .unwrap_or_default();

    let endpoint = trusttunnel_settings::endpoint_from_deeplink_config(config)
        .unwrap_or_else(|e| panic!("Failed to convert deep-link config: {}", e));

    display_and_confirm_endpoint(&endpoint, &cert_infos);

    endpoint
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use trusttunnel_deeplink::{DeepLinkConfig, Protocol};

    #[test]
    fn test_deeplink_field_mapping() {
        // Encode a config, then decode it and verify the field mapping
        let config = DeepLinkConfig {
            hostname: "test.host".to_string(),
            addresses: vec![
                "10.0.0.1:443".parse::<SocketAddr>().unwrap(),
                "[::1]:8443".parse::<SocketAddr>().unwrap(),
            ],
            username: "user1".to_string(),
            password: "pass1".to_string(),
            client_random_prefix: Some("aabb".to_string()),
            custom_sni: Some("sni.host".to_string()),
            has_ipv6: false,
            skip_verification: true,
            certificate: None,
            upstream_protocol: Protocol::Http3,
            anti_dpi: true,
        };

        let uri = trusttunnel_deeplink::encode(&config).unwrap();
        let decoded = trusttunnel_deeplink::decode(&uri).unwrap();

        assert_eq!(decoded.hostname, "test.host");
        assert_eq!(decoded.addresses.len(), 2);
        assert_eq!(decoded.username, "user1");
        assert_eq!(decoded.password, "pass1");
        assert_eq!(decoded.client_random_prefix, Some("aabb".to_string()));
        assert_eq!(decoded.custom_sni, Some("sni.host".to_string()));
        assert!(!decoded.has_ipv6);
        assert!(decoded.skip_verification);
        assert!(decoded.certificate.is_none());
        assert_eq!(decoded.upstream_protocol, Protocol::Http3);
        assert!(decoded.anti_dpi);
    }

    #[test]
    fn test_verify_deeplink_certificates_empty() {
        let result = std::panic::catch_unwind(|| verify_deeplink_certificates(&[]));
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_deeplink_certificates_invalid_der() {
        let result = std::panic::catch_unwind(|| verify_deeplink_certificates(&[0xFF, 0x00, 0x01]));
        assert!(result.is_err());
    }
}
