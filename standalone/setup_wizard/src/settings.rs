use std::{fs, path};
use std::fs::File;
use std::io::BufReader;
use std::ops::Not;
use serde::{Deserialize, Serialize};
use x509_parser::extensions::GeneralName;
use crate::Mode;
use crate::user_interaction::{ask_for_agreement, ask_for_agreement_with_default, ask_for_input, ask_for_password, checked_overwrite, select_variant};

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

docgen! {
    #{doc("The set of endpoint connection settings")}
    #[derive(Default, Deserialize, Serialize)]
    pub struct Endpoint {
        #{doc("Endpoint host name, used for TLS session establishment")}
        pub hostname: String,
        #{doc(r#"Endpoint addresses.
The exact address is selected by the pinger. Absence of IPv6 addresses in
the list makes the VPN client reject IPv6 connections which must be routed
through the endpoint with unreachable code."#)}
        pub addresses: Vec<String>,
        #{doc("Whether IPv6 traffic can be routed through the endpoint")}
        #[serde(default = "Endpoint::default_has_ipv6")]
        pub has_ipv6: bool,
        #{doc("Username for authorization")}
        pub username: String,
        #{doc("Password for authorization")}
        pub password: String,
        #{doc("TLS client random prefix (hex string)")}
        #[serde(default)]
        pub client_random: String,
        #{doc(r#"Skip the endpoint certificate verification?
That is, any certificate is accepted with this one set to true."#)}
        #[serde(default)]
        pub skip_verification: bool,
        #{doc(r#"Endpoint certificate in PEM format.
If not specified, the endpoint certificate is verified using the system storage."#)}
        pub certificate: Option<String>,
        #{doc("Protocol to be used to communicate with the endpoint [http2, http3]")}
        #[serde(default)]
        pub upstream_protocol: String,
        #{doc("Fallback protocol to be used in case the main one fails [<none>, http2, http3]")}
        pub upstream_fallback_protocol: Option<String>,
        #{doc("Is anti-DPI measures should be enabled")}
        #[serde(default)]
        pub anti_dpi: bool,
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
On Linux and Windows, it is detected automatically if not specified.
On macOS, it defaults to `en0` if not specified.
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

    pub fn default_post_quantum_group_enabled() -> bool {
        false
    }
}

impl Endpoint {
    pub fn default_upstream_protocol() -> String {
        "http2".into()
    }

    pub fn default_has_ipv6() -> bool {
        true
    }

    pub fn default_anti_dpi() -> bool {
        false
    }

    pub fn default_skip_verification() -> bool {
        false
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
        }.into()
    }
}

impl SocksListener {
    pub fn default_address() -> String {
        "127.0.0.1:1080".into()
    }
}

impl TunListener {
    pub fn default_bound_if() -> String {
        if cfg!(target_os = "macos") {
            "en0"
        } else {
            ""
        }.into()
    }

    pub fn default_included_routes() -> Vec<String> {
        vec![
            "0.0.0.0/0".into(),
            "2000::/3".into(),
        ]
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
        1500
    }
}

macro_rules! opt_field {
    ($x:expr, $field:ident) => {
        $x.map(|x| &x.$field)
    }
}

pub fn build(template: Option<&Settings>) -> Settings {
    Settings {
        loglevel: opt_field!(template, loglevel).cloned()
            .unwrap_or_else(Settings::default_loglevel),
        vpn_mode: select_variant(
            format!("{}\n", Settings::doc_vpn_mode()),
            Settings::available_vpn_modes(),
            Settings::available_vpn_modes().iter()
                .position(|x| *x == opt_field!(template, vpn_mode).cloned()
                    .unwrap_or_else(Settings::default_vpn_mode)
                    .as_str()),
        ).into(),
        killswitch_enabled: opt_field!(template, killswitch_enabled).cloned()
            .unwrap_or_else(Settings::default_killswitch_enabled),
        post_quantum_group_enabled: opt_field!(template, post_quantum_group_enabled).cloned()
            .unwrap_or_else(Settings::default_post_quantum_group_enabled),
        exclusions: opt_field!(template, exclusions).cloned()
            .unwrap_or_default(),
        dns_upstreams: opt_field!(template, dns_upstreams).cloned()
            .unwrap_or_default(),
        endpoint: build_endpoint(opt_field!(template, endpoint)),
        listener: build_listener(opt_field!(template, listener)),
    }
}

fn build_endpoint(template: Option<&Endpoint>) -> Endpoint {
    let predefined_params = crate::get_predefined_params().clone();
    let endpoint_config: Option<EndpointConfig> = empty_to_none(ask_for_input("Path to endpoint config, empty if no", predefined_params.endpoint_config.or(Some("".to_string()))))
        .and_then(|x| {
            fs::read_to_string(&x)
                .map_err(|e| { panic!("Failed to read endpoint config file:\n{}", e.to_string()) })
                .ok()
        })
        .and_then(|x| {
            toml::de::from_str(x.as_str())
                .map_err(|e| { panic!("Failed to parse endpoint config:\n{}", e.to_string()) })
                .ok()
        });
    let mut x = Endpoint {
        addresses: endpoint_config.as_ref()
            .and_then(|x| {
                x.addresses.clone().into()
            })
            .or_else(|| {
                ask_for_input::<String>(
                    &format!("{}\nMust be delimited by whitespace.\n", Endpoint::doc_addresses()),
                    predefined_params.endpoint_addresses
                        .or(opt_field!(template, addresses).cloned())
                        .map(|x| x.join(" ")),
                    )
                    .split_whitespace()
                    .map(String::from)
                    .collect::<Vec<String>>().into()
            })
            .unwrap(),
        has_ipv6: endpoint_config.as_ref()
            .and_then(|x| {
                x.has_ipv6.into()
            })
            .or(opt_field!(template, has_ipv6).cloned())
            .unwrap_or_else(Endpoint::default_has_ipv6),
        username: endpoint_config.as_ref()
            .and_then(|x| {
                x.username.clone().into()
            })
            .or_else(|| {
                ask_for_input(
                    Endpoint::doc_username(),
                    predefined_params.credentials.clone().unzip().0
                        .or(opt_field!(template, username).cloned())
                    )
                    .into()
            })
            .unwrap(),
        password: endpoint_config.as_ref()
            .and_then(|x| {
                x.password.clone().into()
            })
            .or_else(|| {
                predefined_params.credentials.unzip().1
                    .unwrap_or_else(|| opt_field!(template, password).cloned()
                        .and_then(empty_to_none)
                        .and_then(|x| ask_for_agreement("Overwrite password?").not().then_some(x))
                        .unwrap_or_else(|| ask_for_password(Endpoint::doc_password()))
                    )
                    .into()
            })
            .unwrap(),
        client_random: endpoint_config.as_ref()
            .and_then(|x| {
                x.client_random.clone().into()
            })
            .or(opt_field!(template, client_random).cloned())
            .unwrap_or_default(),
        skip_verification: endpoint_config.as_ref()
            .and_then(|x| {
                x.skip_verification.into()
            })
            .or(opt_field!(template, skip_verification).cloned())
            .unwrap_or_else(Endpoint::default_skip_verification),
        upstream_protocol: endpoint_config.as_ref()
            .and_then(|x| {
                x.upstream_protocol.clone().into()
            })
            .or(opt_field!(template, upstream_protocol).cloned())
            .unwrap_or_else(Endpoint::default_upstream_protocol),
        upstream_fallback_protocol: endpoint_config.as_ref()
            .and_then(|x| {
                x.upstream_fallback_protocol.clone().into()
            })
            .or(opt_field!(template, upstream_fallback_protocol).cloned().flatten()),
        anti_dpi: endpoint_config.as_ref()
            .and_then(|x| {
                x.anti_dpi.into()
            })
            .or(opt_field!(template, anti_dpi).cloned())
            .unwrap_or_else(Endpoint::default_anti_dpi),
        ..Default::default()
    };

    if endpoint_config.is_some() {
        let config = endpoint_config.as_ref().unwrap();
        x.hostname = config.hostname.clone();
        x.certificate = config.certificate.clone().into();
    } else {
        let (hostname, certificate) = if crate::get_mode() == Mode::NonInteractive {
            (predefined_params.hostname.clone(), predefined_params.certificate
                                                    .and_then(|x| {
                                                        fs::read_to_string(&x).expect("Failed to read certificate").into()
                                                    }))
        } else if let Some(cert) = opt_field!(template, certificate).cloned().flatten()
            .and_then(parse_cert)
            .and_then(|x|
                ask_for_agreement(&format!("Use an existent certificate? {:?}", x))
                    .then_some(x)
            )
        {
            (Some(cert.common_name), opt_field!(template, certificate).cloned().flatten())
        } else if let Some(cert) = empty_to_none(ask_for_input::<String>(
            &format!("{}\nEnter a path to certificate:", Endpoint::doc_certificate()),
            None,
        )) {
            let contents = fs::read_to_string(& cert).expect("Failed to read certificate");
            match parse_cert(contents.clone()) {
                Some(parsed) => {
                    (Some(parsed.common_name), Some(contents))
                }
                None => {
                    panic!("Couldn't parse provided certificate");
                }
            }
        } else {
            (None, None)
        };

        x.hostname = ask_for_input(
            Endpoint::doc_hostname(),
            predefined_params.hostname
                .or(opt_field!(template, hostname).cloned())
                .or(hostname),
        );
        x.certificate = certificate;
    }

    if x.certificate.is_some() {
        parse_cert(x.certificate.clone().unwrap()).expect("Couldn't parse provided certificate");
    }

    x.skip_verification = x.certificate.is_none()
        && ask_for_agreement_with_default(
        &format!("{}\n", Endpoint::doc_skip_verification()),
        opt_field!(template, skip_verification).cloned().unwrap_or_default(),
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
        Listener::available_kinds().iter()
            .position(|x| *x == template.map(Listener::to_kind_string)
                .unwrap_or_else(Listener::default_kind)
                .as_str()),
    ) {
        "socks" => {
            let template = template.and_then(|x| match x {
                Listener::Socks(x) => Some(x),
                _ => None,
            });
            Listener::Socks(SocksListener {
                address: ask_for_input(
                    SocksListener::doc_address(),
                    Some(opt_field!(template, address).cloned()
                        .unwrap_or_else(SocksListener::default_address)),
                ),
                username: empty_to_none(ask_for_input(
                    SocksListener::doc_username(),
                    Some(opt_field!(template, username).cloned().flatten().unwrap_or_default()),
                )),
                password: empty_to_none(ask_for_input(
                    SocksListener::doc_password(),
                    Some(opt_field!(template, password).cloned().flatten().unwrap_or_default()),
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
                        Some(opt_field!(template, bound_if).cloned()
                            .unwrap_or_else(TunListener::default_bound_if)),
                    )
                },
                included_routes: opt_field!(template, included_routes).cloned()
                    .unwrap_or_else(TunListener::default_included_routes),
                excluded_routes: opt_field!(template, excluded_routes).cloned()
                    .unwrap_or_else(TunListener::default_excluded_routes),
                mtu_size: opt_field!(template, mtu_size).cloned()
                    .unwrap_or_else(TunListener::default_mtu_size),
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
    upstream_fallback_protocol: String,
    #[serde(default)]
    anti_dpi: bool,
}

#[derive(Debug)]
struct Cert {
    common_name: String,
    #[allow(dead_code)] // needed only for logging
    alt_names: Vec<String>,
    #[allow(dead_code)] // needed only for logging
    expiration_date: String,
}

fn lookup_existent_cert() -> Option<Cert> {
    fs::read_dir(".").ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.metadata().map(|meta| meta.is_file()).unwrap_or_default())
        .filter_map(|entry| entry.path().to_str().map(String::from))
        .find_map(parse_cert)
}

fn parse_cert(contents: String) -> Option<Cert> {
    let cert = rustls_pemfile::certs(&mut contents.as_bytes())
        .ok()?
        .into_iter()
        .map(rustls::Certificate)
        .next()?;
    let cert = x509_parser::parse_x509_certificate(&cert.0).ok()?.1;
    Some(Cert {
        common_name: cert.validity.is_valid()
            .then(|| {
                let x = cert.subject.to_string();
                x.as_str()
                    .strip_prefix("CN=")
                    .map(String::from)
                    .unwrap_or(x)
            })?,
        alt_names: cert.subject_alternative_name().ok().flatten()
            .map(|x| x.value.general_names.iter().map(GeneralName::to_string).collect())
            .unwrap_or_default(),
        expiration_date: cert.validity.not_after.to_string(),
    })
}
