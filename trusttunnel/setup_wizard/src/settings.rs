pub use trusttunnel_settings::{Endpoint, Listener, Settings, SocksListener, TunListener};

use crate::subscription;
use crate::user_interaction::{
    ask_for_agreement, ask_for_agreement_with_default, ask_for_input, ask_for_input_raw_line,
    ask_for_password, select_variant,
};
use crate::Mode;
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::ops::Not;
use x509_parser::extensions::GeneralName;

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
        exclusions_tcp_early_ack_enabled: opt_field!(template, exclusions_tcp_early_ack_enabled)
            .cloned()
            .unwrap_or_else(Settings::default_exclusions_tcp_early_ack_enabled),
        exclusions_preresolve_enabled: opt_field!(template, exclusions_preresolve_enabled)
            .cloned()
            .unwrap_or_else(Settings::default_exclusions_preresolve_enabled),
        exclusions_preresolve_max_queries: opt_field!(template, exclusions_preresolve_max_queries)
            .cloned()
            .unwrap_or_else(Settings::default_exclusions_preresolve_max_queries),
        exclusions_scannable_ports: opt_field!(template, exclusions_scannable_ports)
            .cloned()
            .unwrap_or_else(Settings::default_exclusions_scannable_ports),
        exclusions: opt_field!(template, exclusions)
            .cloned()
            .unwrap_or_default(),
        endpoint: build_endpoint(opt_field!(template, endpoint)),
        listener: build_listener(opt_field!(template, listener)),
    }
}

fn build_endpoint(template: Option<&Endpoint>) -> Endpoint {
    let predefined_params = crate::get_predefined_params().clone();

    // Pick the import source: a deep-link (CLI flag or interactive choice),
    // an endpoint config file, or a bare subscription URL; none of those
    // means manual assembly below.
    let mut deeplink_uri = predefined_params.deeplink.clone();

    // A bare --subscription-url is itself an import source in non-interactive
    // mode; in interactive mode it only pre-selects the source in the menu.
    let mut subscription_url = if crate::get_mode() == Mode::NonInteractive {
        predefined_params.subscription_url.clone()
    } else {
        None
    };

    let endpoint_config: Option<EndpointConfig> = if deeplink_uri.is_some() {
        None
    } else if crate::get_mode() == Mode::Interactive && predefined_params.endpoint_config.is_none()
    {
        let selection = crate::user_interaction::select_index(
            "How would you like to provide endpoint configuration?",
            &[
                "Endpoint config file",
                "Deep-link URI (tt://...)",
                "Subscription URL (https://...)",
            ],
            Some(if predefined_params.subscription_url.is_some() {
                2
            } else {
                0
            }),
        );
        match selection {
            0 => read_endpoint_config(empty_to_none(ask_for_input(
                "Path to endpoint config, empty if no",
                Some("".to_string()),
            ))),
            1 => {
                deeplink_uri = Some(ask_for_input_raw_line("Paste deep-link URI"));
                None
            }
            2 => {
                subscription_url = Some(ask_for_input(
                    "Subscription URL",
                    predefined_params
                        .subscription_url
                        .clone()
                        .or(Some("".to_string())),
                ));
                None
            }
            _ => unreachable!(),
        }
    } else {
        read_endpoint_config(empty_to_none(ask_for_input(
            "Path to endpoint config, empty if no",
            predefined_params
                .endpoint_config
                .clone()
                .or(Some("".to_string())),
        )))
    };
    // Build the candidate from the selected import source.
    let mut x = if let Some(uri) = deeplink_uri.as_deref() {
        endpoint_from_deeplink(uri)
    } else if let Some(config) = &endpoint_config {
        candidate_from_endpoint_config(config)
    } else if let Some(url) = subscription_url.as_deref() {
        candidate_from_subscription_url(url.to_string())
    } else {
        build_endpoint_manually(template, &predefined_params)
    };

    // Explicit CLI values override whatever the import source provides.
    // Set before the fetch so they also win over the subscription response.
    if let Some(name) = &predefined_params.name {
        x.name = Some(name.clone());
    }
    if !predefined_params.dns.is_empty() {
        x.dns_upstreams = predefined_params.dns.clone();
    }

    // Fetch the subscription before the configuration is presented to the
    // user, so the confirmation shows the live parameters. A failed fetch is
    // fatal for a subscription-only import; when the import source also
    // carried complete static parameters, warn and keep them.
    if x.subscription.is_some() {
        match subscription::fetch_and_apply(&mut x) {
            Ok(()) => {}
            Err(error) if is_complete(&x) => {
                eprintln!(
                    "WARNING: Could not fetch the subscription; the exported parameters may be stale ({error})"
                );
            }
            Err(error) => {
                eprintln!("Could not fetch the subscription: {error}");
                std::process::exit(1);
            }
        }
    }

    // Imports carry skip_verification from their source; only ask for it
    // when assembling the endpoint manually.
    if deeplink_uri.is_none() && endpoint_config.is_none() && subscription_url.is_none() {
        x.skip_verification = x.certificate.is_none()
            && ask_for_agreement_with_default(
                &format!("{}\n", Endpoint::doc_skip_verification()),
                opt_field!(template, skip_verification)
                    .cloned()
                    .unwrap_or_default(),
            );
    }

    // Confirm or override the creation-only fields interactively, whatever
    // the source was.
    if crate::get_mode() == Mode::Interactive {
        let name = ask_for_input::<String>("Server name", x.name.clone().or(Some("".to_string())));
        if !name.is_empty() {
            x.name = Some(name);
        }
        let dns = ask_for_input::<String>(
            &format!("{}\nDelimit by whitespace.", Endpoint::doc_dns_upstreams()),
            Some(x.dns_upstreams.join(" ")),
        );
        if !dns.is_empty() {
            x.dns_upstreams = dns.split_whitespace().map(str::to_string).collect();
        }
    }

    // Compute the summary after any subscription fetch: the fetch may have
    // replaced the certificate, and the confirmation must describe the one
    // being exported.
    let cert_infos = x
        .certificate
        .as_deref()
        .map(cert_infos_from_pem)
        .unwrap_or_default();

    display_and_confirm_endpoint(&x, &cert_infos);

    x
}

fn build_endpoint_manually(
    template: Option<&Endpoint>,
    predefined_params: &crate::PredefinedParameters,
) -> Endpoint {
    let mut x = Endpoint {
        addresses: ask_for_input::<String>(
            &format!(
                "{}\nMust be delimited by whitespace.\n",
                Endpoint::doc_addresses()
            ),
            predefined_params
                .endpoint_addresses
                .clone()
                .or(opt_field!(template, addresses).cloned())
                .map(|x| x.join(" ")),
        )
        .split_whitespace()
        .map(String::from)
        .collect(),
        has_ipv6: opt_field!(template, has_ipv6)
            .cloned()
            .unwrap_or_else(Endpoint::default_has_ipv6),
        username: ask_for_input(
            Endpoint::doc_username(),
            predefined_params
                .credentials
                .clone()
                .unzip()
                .0
                .or(opt_field!(template, username).cloned()),
        ),
        password: predefined_params
            .credentials
            .clone()
            .unzip()
            .1
            .unwrap_or_else(|| {
                opt_field!(template, password)
                    .cloned()
                    .and_then(empty_to_none)
                    .and_then(|x| ask_for_agreement("Overwrite password?").not().then_some(x))
                    .unwrap_or_else(|| ask_for_password(Endpoint::doc_password()))
            }),
        client_random: opt_field!(template, client_random)
            .cloned()
            .unwrap_or_default(),
        skip_verification: opt_field!(template, skip_verification)
            .cloned()
            .unwrap_or_else(Endpoint::default_skip_verification),
        upstream_protocol: opt_field!(template, upstream_protocol)
            .cloned()
            .unwrap_or_else(Endpoint::default_upstream_protocol),
        tls_profile: opt_field!(template, tls_profile)
            .cloned()
            .unwrap_or_else(Endpoint::default_tls_profile),
        anti_dpi: opt_field!(template, anti_dpi)
            .cloned()
            .unwrap_or_else(Endpoint::default_anti_dpi),
        // Asked by the creation-only confirmation after the endpoint is built
        dns_upstreams: opt_field!(template, dns_upstreams)
            .cloned()
            .unwrap_or_default(),
        name: opt_field!(template, name).cloned().flatten(),
        subscription: opt_field!(template, subscription).cloned().flatten(),
        ..Default::default()
    };

    let (hostname, certificate) = if crate::get_mode() == Mode::NonInteractive {
        (
            predefined_params.hostname.clone(),
            predefined_params.certificate.clone().and_then(|x| {
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
            .clone()
            .or(opt_field!(template, hostname).cloned())
            .or(hostname),
    );
    x.custom_sni = empty_to_none(ask_for_input(
        &format!("{}\nLeave empty if not needed.", Endpoint::doc_custom_sni()),
        predefined_params
            .custom_sni
            .clone()
            .or(opt_field!(template, custom_sni).cloned())
            .or(Some("".to_string())),
    ))
    .unwrap_or_default();
    x.certificate = certificate;

    x
}

fn read_endpoint_config(path: Option<String>) -> Option<EndpointConfig> {
    path.and_then(|x| {
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
                tcp_recv_buf_size: opt_field!(template, tcp_recv_buf_size)
                    .cloned()
                    .unwrap_or_else(TunListener::default_tcp_recv_buf_size),
                tcp_send_buf_size: opt_field!(template, tcp_send_buf_size)
                    .cloned()
                    .unwrap_or_else(TunListener::default_tcp_send_buf_size),
                change_system_dns: ask_for_agreement_with_default(
                    &format!("{}\n", TunListener::doc_change_system_dns()),
                    opt_field!(template, change_system_dns)
                        .cloned()
                        .unwrap_or_else(TunListener::default_change_system_dns),
                ),
                device_name: opt_field!(template, device_name)
                    .cloned()
                    .unwrap_or_else(TunListener::default_device_name),
                use_existing: opt_field!(template, use_existing)
                    .cloned()
                    .unwrap_or_else(TunListener::default_use_existing),
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
    #[serde(default, alias = "client_random_prefix")]
    client_random: String,
    #[serde(default)]
    skip_verification: bool,
    #[serde(default)]
    certificate: String,
    #[serde(default)]
    upstream_protocol: String,
    #[serde(default)]
    tls_profile: String,
    #[serde(default)]
    anti_dpi: bool,
    #[serde(default)]
    custom_sni: String,
    #[serde(default)]
    dns_upstreams: Vec<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    subscription_url: Option<String>,
}

/// Normalize one import source into a candidate endpoint, before any subscription overlay runs
fn candidate_from_endpoint_config(config: &EndpointConfig) -> Endpoint {
    Endpoint {
        hostname: config.hostname.clone(),
        addresses: config.addresses.clone(),
        has_ipv6: config.has_ipv6,
        username: config.username.clone(),
        password: config.password.clone(),
        client_random: config.client_random.clone(),
        skip_verification: config.skip_verification,
        certificate: empty_to_none(config.certificate.clone()),
        upstream_protocol: config.upstream_protocol.clone(),
        tls_profile: empty_to_none(config.tls_profile.clone())
            .unwrap_or_else(Endpoint::default_tls_profile),
        anti_dpi: config.anti_dpi,
        custom_sni: config.custom_sni.clone(),
        dns_upstreams: config.dns_upstreams.clone(),
        name: empty_to_none(config.name.clone()),
        subscription: config.subscription_url.clone().map(|url| {
            trusttunnel_settings::EndpointSubscription {
                url,
                last_fetched_at: None,
            }
        }),
    }
}

/// Build a candidate carrying only a subscription URL; the subscription
/// fetch fills in everything else.
fn candidate_from_subscription_url(url: String) -> Endpoint {
    Endpoint {
        subscription: Some(trusttunnel_settings::EndpointSubscription {
            url,
            last_fetched_at: None,
        }),
        ..Endpoint::default()
    }
}

/// Check that the fields required to connect are all non-empty
fn is_complete(endpoint: &Endpoint) -> bool {
    !endpoint.hostname.is_empty()
        && !endpoint.addresses.is_empty()
        && endpoint.addresses.iter().all(|a| !a.is_empty())
        && !endpoint.username.is_empty()
        && !endpoint.password.is_empty()
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

        let dns_upstreams = if ep.dns_upstreams.is_empty() {
            "(default: AdGuard DNS unfiltered)".to_string()
        } else {
            ep.dns_upstreams.join(", ")
        };

        write!(
            f,
            "
  Name:              {}
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
  TLS profile:       {}
  Anti-DPI:          {}
  DNS upstreams:     {}",
            ep.name.as_deref().unwrap_or("(none)"),
            ep.hostname,
            addresses,
            custom_sni,
            if ep.has_ipv6 { "yes" } else { "no" },
            ep.username,
            client_random,
            if ep.skip_verification { "yes" } else { "no" },
            cert_display,
            ep.upstream_protocol,
            ep.tls_profile,
            if ep.anti_dpi { "yes" } else { "no" },
            dns_upstreams,
        )
    }
}

/// Parse a PEM certificate bundle and collect the summary info for the
/// confirmation display. Panic on a malformed, empty or expired bundle.
fn cert_infos_from_pem(pem: &str) -> Vec<CertInfo> {
    let certs =
        rustls_pemfile::certs(&mut pem.as_bytes()).expect("Failed to parse PEM certificates");

    if certs.is_empty() {
        panic!("The certificate bundle contains no valid certificates");
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
        eprintln!("Endpoint configuration declined by user.");
        std::process::exit(1);
    }
}

/// Decode the deep-link and return the endpoint it describes. The
/// certificate is validated when the confirmation summary is built, after
/// any subscription fetch has overlaid the live parameters.
pub fn endpoint_from_deeplink(uri: &str) -> Endpoint {
    let config = trusttunnel_deeplink::decode(uri)
        .unwrap_or_else(|e| panic!("Failed to decode deep-link URI: {}", e));
    trusttunnel_settings::endpoint_from_deeplink_config(config)
        .unwrap_or_else(|e| panic!("Failed to convert deep-link config: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusttunnel_deeplink::{DeepLinkConfig, Protocol};

    #[test]
    fn test_deeplink_field_mapping() {
        // Encode a config, then decode it and verify the field mapping
        let config = DeepLinkConfig {
            hostname: Some("test.host".to_string()),
            addresses: vec![
                "10.0.0.1:443".parse().unwrap(),
                "[::1]:8443".parse().unwrap(),
            ],
            username: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            client_random_prefix: Some("aabb".to_string()),
            custom_sni: Some("sni.host".to_string()),
            has_ipv6: false,
            skip_verification: true,
            certificate: None,
            upstream_protocol: Protocol::Http3,
            anti_dpi: true,
            dns_upstreams: vec!["tls://dns.adguard-dns.com".to_string()],
            name: Some("Example VPN".to_string()),
            subscription_url: None,
        };

        let uri = trusttunnel_deeplink::encode(&config).unwrap();
        let decoded = trusttunnel_deeplink::decode(&uri).unwrap();

        assert_eq!(decoded.hostname.as_deref(), Some("test.host"));
        assert_eq!(decoded.addresses.len(), 2);
        assert_eq!(decoded.username.as_deref(), Some("user1"));
        assert_eq!(decoded.password.as_deref(), Some("pass1"));
        assert_eq!(decoded.client_random_prefix, Some("aabb".to_string()));
        assert_eq!(decoded.custom_sni, Some("sni.host".to_string()));
        assert!(!decoded.has_ipv6);
        assert!(decoded.skip_verification);
        assert!(decoded.certificate.is_none());
        assert_eq!(decoded.upstream_protocol, Protocol::Http3);
        assert!(decoded.anti_dpi);
    }

    // A self-signed certificate valid until 2126; generated once for the tests.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIICzzCCAbegAwIBAgIUa7LC0WpYc7i8r38ipmuQTGcsyKMwDQYJKoZIhvcNAQEL\n\
        BQAwDzENMAsGA1UEAwwEdGVzdDAgFw0yNjEwMDUxOTI4MTJaGA8yMTI2MDkxMTE5\n\
        MjgxMlowDzENMAsGA1UEAwwEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n\
        AQoCggEBALtq62lU79lRSqdRZTPO9TQzPFZeJQF9RAG2ujS9P6I19cZnTq7nJki1\n\
        rm8bKVxj9BLtwU8WGojXPf5HVbDR47cTYTJZ4XnuOX7TQPZCwQ/fuzfyr77r+JgC\n\
        ozea+w6HQmq9sZ8sYYRja8gsMPRtLizFIuBGUm9VdWm2oW8EXFjBbZ67jZ2nDQEK\n\
        iAlLHnc6imqimgmlPpOwmwh0TgD9MZQ46V9jLDfvNAztmZrvRURngN1fKAJdeZxZ\n\
        xfXgvxMeMKJIuRucPr1+QL54ZjrQWUmxb+4X+hjw+gYtNe5VEQBW99qrPJyg9PFG\n\
        Ottg3j0rRTRccHW9zYVA6dqaA4fgOgMCAwEAAaMhMB8wHQYDVR0OBBYEFKEOCvDy\n\
        mr6cqa/3qphZ81uSaCAyMA0GCSqGSIb3DQEBCwUAA4IBAQCBfyAQlBfyW+f+B84W\n\
        /Yry+XwNzu6+to8PjZ0nagRsq/kqR4ew5/oOP4pf6coPbRYXvGN0hvytj20vs5Iv\n\
        2I6Demdjw6Bp9GXW2Q/QfkMwmmvcAa2zMJtvKc8DxrFz0eMBd7nbfBfIaqvPLyiG\n\
        /XOmKlJEJvj9z+nWPNLUSd4fkxQRP0thOKDfsu5A9m9C/fSmw51VshV20+RxTrGg\n\
        0dSlzHhl0woopVKcb+PGoCQ5T9OhwZPGDGLlrSZyWZv19CkpbTPe7fDN7mDvbt+n\n\
        Nls8iCgCQwB8pRfuJD68kDQMmtJHmkUtpxD8WAiRgs/yzUYXFawRvdPfoWml87jx\n\
        BO6G\n\
        -----END CERTIFICATE-----\n";

    #[test]
    fn cert_infos_from_pem_reads_certificate_summary() {
        let infos = cert_infos_from_pem(TEST_CERT_PEM);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].common_name, "test");
        assert!(infos[0].expiration_date.contains("2126"));
    }

    #[test]
    fn cert_infos_from_pem_rejects_garbage() {
        let result = std::panic::catch_unwind(|| cert_infos_from_pem("not a pem"));
        assert!(result.is_err());
    }

    #[test]
    fn cert_infos_from_pem_rejects_empty_bundle() {
        let result = std::panic::catch_unwind(|| cert_infos_from_pem(""));
        assert!(result.is_err());
    }

    #[test]
    fn endpoint_config_reads_client_random_prefix() {
        let toml_str = r#"
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
client_random_prefix = "aabb/16"
"#;
        let config: EndpointConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.client_random, "aabb/16");
    }

    #[test]
    fn endpoint_config_still_reads_client_random() {
        let toml_str = "client_random = \"ccdd\"\n";
        let config: EndpointConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.client_random, "ccdd");
    }

    #[test]
    fn endpoint_config_reads_subscription_url() {
        let toml_str = r#"
hostname = "vpn.example.com"
subscription_url = "https://u:p@vpn.example.com/subscription"
"#;
        let config: EndpointConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.subscription_url.as_deref(),
            Some("https://u:p@vpn.example.com/subscription")
        );
    }

    #[test]
    fn candidate_from_endpoint_config_carries_subscription() {
        let config: EndpointConfig = toml::from_str(
            r#"
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
subscription_url = "https://u:p@vpn.example.com/subscription"
"#,
        )
        .unwrap();
        let candidate = candidate_from_endpoint_config(&config);
        assert_eq!(candidate.hostname, "vpn.example.com");
        assert_eq!(
            candidate.subscription.as_ref().map(|s| s.url.as_str()),
            Some("https://u:p@vpn.example.com/subscription")
        );
        assert!(candidate.subscription.unwrap().last_fetched_at.is_none());
    }

    #[test]
    fn candidate_without_subscription_url_has_no_table() {
        let config: EndpointConfig = toml::from_str("hostname = \"h\"\n").unwrap();
        let candidate = candidate_from_endpoint_config(&config);
        assert!(candidate.subscription.is_none());
    }

    #[test]
    fn candidate_from_endpoint_config_maps_name() {
        let config: EndpointConfig = toml::from_str("name = \"Example VPN\"\n").unwrap();
        let candidate = candidate_from_endpoint_config(&config);
        assert_eq!(candidate.name.as_deref(), Some("Example VPN"));
    }

    #[test]
    fn completeness_matches_cpp_build_endpoint() {
        let mut endpoint = trusttunnel_settings::Endpoint::default();
        assert!(!is_complete(&endpoint));
        endpoint.hostname = "h".to_string();
        endpoint.addresses = vec!["1.2.3.4:443".to_string()];
        endpoint.username = "u".to_string();
        endpoint.password = "p".to_string();
        assert!(is_complete(&endpoint));
        endpoint.addresses = vec!["".to_string()];
        assert!(!is_complete(&endpoint));
    }

    #[test]
    fn bare_url_candidate_is_subscription_only() {
        let candidate = candidate_from_subscription_url("https://u:p@h/s".to_string());
        assert!(!is_complete(&candidate));
        assert_eq!(
            candidate.subscription.as_ref().map(|s| s.url.as_str()),
            Some("https://u:p@h/s")
        );
    }
}
