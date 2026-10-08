use serde::{Deserialize, Serialize};
use trusttunnel_deeplink::{DeepLinkConfig, Protocol};

/// Endpoint connection settings. Shared by `setup_wizard` and `deeplink-ffi`.
#[derive(Default, Deserialize, PartialEq, Serialize)]
pub struct Endpoint {
    pub hostname: String,
    pub addresses: Vec<String>,
    #[serde(default = "Endpoint::default_has_ipv6")]
    pub has_ipv6: bool,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub client_random: String,
    #[serde(default)]
    pub skip_verification: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default)]
    pub upstream_protocol: String,
    #[serde(default)]
    pub tls_profile: String,
    #[serde(default)]
    pub anti_dpi: bool,
    #[serde(default)]
    pub custom_sni: String,
    #[serde(default)]
    pub dns_upstreams: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Endpoint {
    pub fn doc() -> &'static str {
        "VPN server endpoint settings"
    }

    pub fn default_has_ipv6() -> bool {
        true
    }

    pub fn default_upstream_protocol() -> String {
        "http2".into()
    }

    pub fn default_tls_profile() -> String {
        "chrome".into()
    }

    pub fn default_anti_dpi() -> bool {
        false
    }

    pub fn default_skip_verification() -> bool {
        false
    }

    pub fn doc_hostname() -> &'static str {
        "Endpoint host name, used for TLS session establishment"
    }

    pub fn doc_addresses() -> &'static str {
        "Endpoint addresses (IP:port or hostname:port).\n\
         The exact address is selected by the pinger. Hostnames are resolved via DNS\n\
         at connect time."
    }

    pub fn doc_has_ipv6() -> &'static str {
        "Whether IPv6 traffic can be routed through the endpoint"
    }

    pub fn doc_username() -> &'static str {
        "Username for authorization"
    }

    pub fn doc_password() -> &'static str {
        "Password for authorization"
    }

    pub fn doc_client_random() -> &'static str {
        "TLS client random prefix and mask (hex string, format: prefix[/mask])"
    }

    pub fn doc_skip_verification() -> &'static str {
        "Skip the endpoint certificate verification?\n\
         That is, any certificate is accepted with this one set to true."
    }

    pub fn doc_certificate() -> &'static str {
        "Endpoint certificate in PEM format.\n\
         If not specified, the endpoint certificate is verified using the system storage."
    }

    pub fn doc_upstream_protocol() -> &'static str {
        "Protocol to be used to communicate with the endpoint [http2, http3]"
    }

    pub fn doc_tls_profile() -> &'static str {
        "TLS ClientHello fingerprint to mimic [chrome, safari, firefox, okhttp, openssl, default]"
    }

    pub fn doc_anti_dpi() -> &'static str {
        "Is anti-DPI measures should be enabled"
    }

    pub fn doc_custom_sni() -> &'static str {
        "Custom SNI value for TLS handshake.\n\
         If set, this value is used as the TLS SNI instead of the hostname."
    }

    pub fn doc_dns_upstreams() -> &'static str {
        "DNS upstreams. Default: AdGuard DNS unfiltered.\n\
         One of the following kinds:\n\
           * 8.8.8.8:53 -- plain DNS\n\
           * tcp://8.8.8.8:53 -- plain DNS over TCP\n\
           * tls://1.1.1.1 -- DNS-over-TLS\n\
           * https://dns.adguard.com/dns-query -- DNS-over-HTTPS\n\
           * sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)\n\
           * quic://dns.adguard.com:8853 -- DNS-over-QUIC"
    }
}

/// Convert a decoded [`DeepLinkConfig`] into an [`Endpoint`] ready for TOML
/// serialization.
pub fn endpoint_from_deeplink_config(config: DeepLinkConfig) -> Result<Endpoint, String> {
    let certificate = config
        .certificate
        .as_deref()
        .map(trusttunnel_deeplink::cert::der_to_pem)
        .transpose()
        .map_err(|e| e.to_string())?;

    Ok(Endpoint {
        hostname: config.hostname,
        addresses: config.addresses.iter().map(|a| a.to_string()).collect(),
        has_ipv6: config.has_ipv6,
        username: config.username,
        password: config.password,
        client_random: config.client_random_prefix.unwrap_or_default(),
        skip_verification: config.skip_verification,
        certificate,
        upstream_protocol: config.upstream_protocol.to_string(),
        tls_profile: Endpoint::default_tls_profile(),
        anti_dpi: config.anti_dpi,
        custom_sni: config.custom_sni.unwrap_or_default(),
        dns_upstreams: config.dns_upstreams,
        name: config.name,
    })
}

/// Convert an [`Endpoint`] into a [`DeepLinkConfig`] ready for deep-link
/// encoding.
///
/// A missing or empty `certificate` means the endpoint is verified with the
/// system trust store, so the certificate field is omitted. A configured
/// certificate is exported as a DER chain.
///
/// The deep-link format carries only a client random prefix, not a mask, so
/// a `prefix/mask` value is exported as its prefix.
pub fn deeplink_config_from_endpoint(endpoint: &Endpoint) -> Result<DeepLinkConfig, String> {
    let certificate = match endpoint.certificate.as_deref() {
        Some(pem) if !pem.is_empty() => {
            Some(trusttunnel_deeplink::cert::pem_to_der(pem).map_err(|e| e.to_string())?)
        }
        _ => None,
    };

    let upstream_protocol = match endpoint.upstream_protocol.as_str() {
        "http3" => Protocol::Http3,
        "http2" | "auto" | "" => Protocol::Http2,
        other => return Err(format!("unsupported upstream protocol: {other}")),
    };

    Ok(DeepLinkConfig {
        hostname: endpoint.hostname.clone(),
        addresses: endpoint.addresses.clone(),
        username: endpoint.username.clone(),
        password: endpoint.password.clone(),
        client_random_prefix: endpoint.client_random.split('/').next().and_then(non_empty),
        custom_sni: non_empty(&endpoint.custom_sni),
        has_ipv6: endpoint.has_ipv6,
        skip_verification: endpoint.skip_verification,
        certificate,
        upstream_protocol,
        anti_dpi: endpoint.anti_dpi,
        name: endpoint.name.as_deref().and_then(non_empty),
        dns_upstreams: endpoint.dns_upstreams.clone(),
    })
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusttunnel_deeplink::Protocol;

    #[test]
    fn test_deeplink_field_mapping() {
        let config = DeepLinkConfig {
            hostname: "vpn.example.com".to_string(),
            addresses: vec!["1.2.3.4:443".parse().unwrap()],
            username: "alice".to_string(),
            password: "s3cr3t".to_string(),
            client_random_prefix: Some("aabb".to_string()),
            custom_sni: Some("sni.example.com".to_string()),
            has_ipv6: false,
            skip_verification: true,
            certificate: None,
            upstream_protocol: Protocol::Http2,
            anti_dpi: false,
            dns_upstreams: vec!["tls://dns.adguard-dns.com".to_string()],
            name: Some("Example VPN".to_string()),
        };

        let ep = endpoint_from_deeplink_config(config).unwrap();
        assert_eq!(ep.hostname, "vpn.example.com");
        assert_eq!(ep.addresses, vec!["1.2.3.4:443"]);
        assert_eq!(ep.username, "alice");
        assert_eq!(ep.password, "s3cr3t");
        assert_eq!(ep.client_random, "aabb");
        assert_eq!(ep.custom_sni, "sni.example.com");
        assert!(!ep.has_ipv6);
        assert!(ep.skip_verification);
        assert!(ep.certificate.is_none());
        assert_eq!(ep.upstream_protocol, "http2");
        assert!(!ep.anti_dpi);
        assert_eq!(ep.dns_upstreams, vec!["tls://dns.adguard-dns.com"]);
        assert_eq!(ep.name, Some("Example VPN".to_string()));
    }

    #[test]
    fn test_optional_fields_default_to_empty() {
        let config = DeepLinkConfig {
            hostname: "h".to_string(),
            addresses: vec![],
            username: "u".to_string(),
            password: "p".to_string(),
            client_random_prefix: None,
            custom_sni: None,
            has_ipv6: true,
            skip_verification: false,
            certificate: None,
            upstream_protocol: Protocol::Http3,
            anti_dpi: true,
            dns_upstreams: vec![],
            name: None,
        };

        let ep = endpoint_from_deeplink_config(config).unwrap();
        assert_eq!(ep.client_random, "");
        assert_eq!(ep.custom_sni, "");
        assert_eq!(ep.upstream_protocol, "http3");
        assert!(ep.anti_dpi);
        assert!(ep.dns_upstreams.is_empty());
        assert_eq!(ep.name, None);
    }

    #[test]
    fn test_roundtrip_with_dns_upstreams_and_name() {
        let config = DeepLinkConfig {
            hostname: "vpn.example.com".to_string(),
            addresses: vec!["1.2.3.4:443".to_string()],
            username: "alice".to_string(),
            password: "s3cr3t".to_string(),
            client_random_prefix: None,
            custom_sni: None,
            has_ipv6: true,
            skip_verification: false,
            certificate: None,
            upstream_protocol: Protocol::Http2,
            anti_dpi: false,
            dns_upstreams: vec!["tls://dns.adguard-dns.com".to_string()],
            name: Some("Example VPN".to_string()),
        };

        let uri = trusttunnel_deeplink::encode(&config).unwrap();
        let decoded = trusttunnel_deeplink::decode(&uri).unwrap();
        let ep = endpoint_from_deeplink_config(decoded).unwrap();

        assert_eq!(ep.dns_upstreams, vec!["tls://dns.adguard-dns.com"]);
        assert_eq!(ep.name, Some("Example VPN".to_string()));
    }

    #[test]
    fn test_roundtrip_without_dns_upstreams() {
        let config = DeepLinkConfig {
            hostname: "vpn.example.com".to_string(),
            addresses: vec!["1.2.3.4:443".to_string()],
            username: "alice".to_string(),
            password: "s3cr3t".to_string(),
            client_random_prefix: None,
            custom_sni: None,
            has_ipv6: true,
            skip_verification: false,
            certificate: None,
            upstream_protocol: Protocol::Http2,
            anti_dpi: false,
            dns_upstreams: vec![],
            name: None,
        };

        let uri = trusttunnel_deeplink::encode(&config).unwrap();
        let decoded = trusttunnel_deeplink::decode(&uri).unwrap();
        let ep = endpoint_from_deeplink_config(decoded).unwrap();

        assert!(ep.dns_upstreams.is_empty());
        assert_eq!(ep.name, None);
    }

    #[test]
    fn test_toml_deserialization_absent_fields() {
        let toml_str = r#"
            hostname = "vpn.example.com"
            addresses = ["1.2.3.4:443"]
            username = "alice"
            password = "s3cr3t"
        "#;
        let ep: Endpoint = toml::from_str(toml_str).unwrap();
        assert!(ep.dns_upstreams.is_empty());
        assert_eq!(ep.name, None);
    }

    #[test]
    fn test_toml_deserialization_present_fields() {
        let toml_str = r#"
            hostname = "vpn.example.com"
            addresses = ["1.2.3.4:443"]
            username = "alice"
            password = "s3cr3t"
            dns_upstreams = ["tls://dns.adguard-dns.com"]
            name = "Example VPN"
        "#;
        let ep: Endpoint = toml::from_str(toml_str).unwrap();
        assert_eq!(ep.dns_upstreams, vec!["tls://dns.adguard-dns.com"]);
        assert_eq!(ep.name, Some("Example VPN".to_string()));
    }

    // Two-certificate PEM chain: leaf (CN=vpn.example.com) + CA (CN=Test CA)
    const TEST_CERT_CHAIN_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIC/DCCAeSgAwIBAgIUCI9VIilTMYZq4JfFnFjCuQsAiGIwDQYJKoZIhvcNAQEL\n\
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjAyMjYxMzEyMDBaFw0yNzAyMjYx\n\
MzEyMDBaMBoxGDAWBgNVBAMMD3Zwbi5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN\n\
AQEBBQADggEPADCCAQoCggEBAKnrz9FwFq2xRpOu0D+2hFwymMaixPr556MuB4P1\n\
nLv8vqRQ3MBZn7p48QTywO5OAqIDL27hpigM1e2tc45UuAuaMYoz+Ryty3O75k9X\n\
sdYaVaupOLNWBtbjNntRzFgMpYwbz+lZYuaKqwdRmCJM71Af2jt7aPGSUXeMMR/A\n\
QZZNlRfQuA6NdmhzNsXjaA6xLDBYPk1nGYnFpMxOTlOD9jhM/lImrAMDBATEoMXO\n\
CyhEclgbJtYla6D5Q5Go3NlbMLPr6zOddoL5g7MkQmerODiWlLAlMPIvC33Bz9FU\n\
Dn5wVJ8G5gSFDjq66cL30a9Gq8lWStuy9d3WeXSY5WcBzoMCAwEAAaNCMEAwHQYD\n\
VR0OBBYEFB/yEYFRHwyDdA8/EaeiIi/padZgMB8GA1UdIwQYMBaAFGuqVmspjq2L\n\
h+FhwZJL3VYEm58DMA0GCSqGSIb3DQEBCwUAA4IBAQBqloNE2yxi/6x3KMOVS4bN\n\
+576mpwU+Kx3bDvAvEP8kNtnvOvLKYATaIHsWK+uHvVjYPf7Nw1InUg3GKnE86IH\n\
mr1PgUri9ECKucg9UkOyzdS2VdeWeL+ME2POpg3ARXici5vUngzcKPQmVBu27PSK\n\
dUgkNHQPSxWkBytrxLBi3dynL5qnyoOfzmXkl1odV5XPE77NtvoR4LD5z1/Tn4a1\n\
StvzAN22qiDLkP4MwOir5r21bShJt4otXyNXFZHA0gE19AjLxmknms8D2v3L4ytx\n\
UGXW9acA8MoG1D+TT6jQjGqupznNL/73xMRYazqFjaVCpmaaSYGP41AkLsHuiMti\n\
-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\n\
MIIDBTCCAe2gAwIBAgIUJQlOhwer2yHQbyhVtk86+1587qowDQYJKoZIhvcNAQEL\n\
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjAyMjYxMzEyMDBaFw0yNzAyMjYx\n\
MzEyMDBaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n\
DwAwggEKAoIBAQCbWJQG4lT5uK571FUQqgZuPcfeCtuvI+WCIfxmGk58zI0wmBDS\n\
zaZroUVvcEV4qva+03hDENsKNTypDDlMrd83qzc3rEOLBezNrSQVlbiTNG7lYHU1\n\
3lw9//BlvNmjVBHcQ0643Q+XilG7sDSt3KuqoAT2CiLxm4A/xVN/uzfAoBZhFn5h\n\
oik448kqXXNh6PsofoZO3jTh+4JZuD++xvj+cVdKzH25UIWWCJxBrNqR9zXo8WO5\n\
UFcxxVWnHSqpS8dvpFGVj6B7kyjZZb7TSYYuEJoMplN3uR25nMHgrXse0mvatCRi\n\
uDygNx6Vzg2R7akQXD0bqBVyRmzKY/xAO7CLAgMBAAGjUzBRMB0GA1UdDgQWBBRr\n\
qlZrKY6ti4fhYcGSS91WBJufAzAfBgNVHSMEGDAWgBRrqlZrKY6ti4fhYcGSS91W\n\
BJufAzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCII03BWTUn\n\
nT2HJrh67ywq34UwWFqqJA0AQIetpS933waW01yr7YJxq3TAznVgsiXKkU/9bFvx\n\
9u4mnzMHy+LJeGw5TtveDmKz22Jr45KH0ug3kikqdPVqB+ur2Kx73ao0SXFCyeIi\n\
6E57QnwyAWmSxIKzjIDreMr0Y2tWRfwvgsRkxZZP3Ps+SQakz6yfYoSJesJxJ0o2\n\
OzTTMTfK4lR2f/QP4MGp8E0dImkfm9eLq6be8VoaNt2nx1MqiD2AxMF3w7FAXmCS\n\
jhjuhML7Zp8c0/3g+r/60sv/9x4DrPeXTYrGCK+qLgZ1qxpwIARNbl780fGnZCIf\n\
omxU7kknZApM\n\
-----END CERTIFICATE-----\n";

    fn sample_endpoint() -> Endpoint {
        Endpoint {
            hostname: "vpn.example.com".into(),
            addresses: vec!["1.2.3.4:443".into(), "[::1]:8443".into()],
            has_ipv6: false,
            username: "alice".into(),
            password: "s3cr3t".into(),
            client_random: "aabb/ffff".into(),
            skip_verification: true,
            certificate: Some(TEST_CERT_CHAIN_PEM.into()),
            upstream_protocol: "http3".into(),
            tls_profile: "chrome".into(),
            anti_dpi: true,
            custom_sni: "sni.example.com".into(),
            dns_upstreams: vec!["tls://dns.adguard-dns.com".into()],
            name: Some("Example VPN".into()),
        }
    }

    #[test]
    fn test_deeplink_config_from_endpoint_maps_fields() {
        let config = deeplink_config_from_endpoint(&sample_endpoint()).unwrap();

        assert_eq!(config.hostname, "vpn.example.com");
        assert_eq!(config.addresses, vec!["1.2.3.4:443", "[::1]:8443"]);
        assert_eq!(config.username, "alice");
        assert_eq!(config.password, "s3cr3t");
        assert_eq!(config.client_random_prefix.as_deref(), Some("aabb"));
        assert_eq!(config.custom_sni.as_deref(), Some("sni.example.com"));
        assert!(!config.has_ipv6);
        assert!(config.skip_verification);
        assert!(config.anti_dpi);
        assert_eq!(config.upstream_protocol, Protocol::Http3);
        assert_eq!(config.name.as_deref(), Some("Example VPN"));
        assert_eq!(config.dns_upstreams, vec!["tls://dns.adguard-dns.com"]);

        let certificate = config.certificate.expect("certificate must be exported");
        let pem = trusttunnel_deeplink::cert::der_to_pem(&certificate).unwrap();
        assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 2);
    }

    #[test]
    fn test_deeplink_config_from_endpoint_omits_empty_optionals() {
        let endpoint = Endpoint {
            hostname: "vpn.example.com".into(),
            addresses: vec!["1.2.3.4:443".into()],
            has_ipv6: true,
            username: "alice".into(),
            password: "s3cr3t".into(),
            ..Default::default()
        };

        let config = deeplink_config_from_endpoint(&endpoint).unwrap();

        assert_eq!(config.client_random_prefix, None);
        assert_eq!(config.custom_sni, None);
        assert_eq!(config.certificate, None);
        assert_eq!(config.name, None);
        assert!(config.dns_upstreams.is_empty());
        assert_eq!(config.upstream_protocol, Protocol::Http2);
        assert!(config.has_ipv6);
    }

    #[test]
    fn test_deeplink_config_from_endpoint_upstream_protocol() {
        let mut endpoint = sample_endpoint();

        endpoint.upstream_protocol = "http3".into();
        assert_eq!(
            deeplink_config_from_endpoint(&endpoint)
                .unwrap()
                .upstream_protocol,
            Protocol::Http3
        );

        for value in ["http2", "auto", ""] {
            endpoint.upstream_protocol = value.into();
            assert_eq!(
                deeplink_config_from_endpoint(&endpoint)
                    .unwrap()
                    .upstream_protocol,
                Protocol::Http2
            );
        }

        endpoint.upstream_protocol = "http1".into();
        assert!(deeplink_config_from_endpoint(&endpoint).is_err());
    }

    #[test]
    fn test_endpoint_deeplink_roundtrip() {
        let endpoint = sample_endpoint();
        let config = deeplink_config_from_endpoint(&endpoint).unwrap();
        let uri = trusttunnel_deeplink::encode(&config).unwrap();
        let decoded = trusttunnel_deeplink::decode(&uri).unwrap();
        let restored = endpoint_from_deeplink_config(decoded).unwrap();

        assert_eq!(restored.hostname, endpoint.hostname);
        assert_eq!(restored.addresses, endpoint.addresses);
        assert_eq!(restored.username, endpoint.username);
        assert_eq!(restored.password, endpoint.password);
        assert_eq!(restored.client_random, "aabb");
        assert_eq!(restored.custom_sni, endpoint.custom_sni);
        assert_eq!(restored.has_ipv6, endpoint.has_ipv6);
        assert_eq!(restored.skip_verification, endpoint.skip_verification);
        assert_eq!(restored.upstream_protocol, "http3");
        assert_eq!(restored.anti_dpi, endpoint.anti_dpi);
        assert_eq!(restored.name, endpoint.name);
        assert_eq!(restored.dns_upstreams, endpoint.dns_upstreams);
        assert!(restored.certificate.is_some());
    }

    #[test]
    fn test_endpoint_export_import_roundtrip() {
        let original = Endpoint {
            hostname: "vpn.example.com".into(),
            addresses: vec!["1.2.3.4:443".into(), "[2001:db8::1]:8443".into()],
            has_ipv6: false,
            username: "alice".into(),
            password: "s3cr3t".into(),
            client_random: "aabbccdd".into(),
            skip_verification: true,
            certificate: Some(TEST_CERT_CHAIN_PEM.into()),
            upstream_protocol: "http3".into(),
            // The deep-link format carries no TLS profile, so it must stay at its default.
            tls_profile: Endpoint::default_tls_profile(),
            anti_dpi: true,
            custom_sni: "sni.example.com".into(),
            dns_upstreams: vec!["tls://dns.adguard-dns.com".into(), "8.8.8.8:53".into()],
            name: Some("Example VPN".into()),
        };

        // Export the settings as a deep-link.
        let config = deeplink_config_from_endpoint(&original).unwrap();
        let uri = trusttunnel_deeplink::encode(&config).unwrap();

        // Reset all settings before importing.
        let mut endpoint = Endpoint::default();
        assert!(
            endpoint != original,
            "reset endpoint must differ from the original"
        );

        // Import the deep-link back into the settings.
        let decoded = trusttunnel_deeplink::decode(&uri).unwrap();
        endpoint = endpoint_from_deeplink_config(decoded).unwrap();

        assert!(
            endpoint == original,
            "endpoint restored from a deep-link must match the original"
        );
    }
}
