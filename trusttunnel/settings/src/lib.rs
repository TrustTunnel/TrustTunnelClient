use serde::{Deserialize, Serialize};
use trusttunnel_deeplink::DeepLinkConfig;

/// Endpoint connection settings. Shared by `setup_wizard` and `deeplink-ffi`.
#[derive(Default, Deserialize, Serialize)]
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
    pub anti_dpi: bool,
    #[serde(default)]
    pub custom_sni: String,
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

    pub fn doc_anti_dpi() -> &'static str {
        "Is anti-DPI measures should be enabled"
    }

    pub fn doc_custom_sni() -> &'static str {
        "Custom SNI value for TLS handshake.\n\
         If set, this value is used as the TLS SNI instead of the hostname."
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
        anti_dpi: config.anti_dpi,
        custom_sni: config.custom_sni.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use trusttunnel_deeplink::Protocol;

    #[test]
    fn test_field_mapping() {
        let config = DeepLinkConfig {
            hostname: "vpn.example.com".to_string(),
            addresses: vec!["1.2.3.4:443".parse::<SocketAddr>().unwrap()],
            username: "alice".to_string(),
            password: "s3cr3t".to_string(),
            client_random_prefix: Some("aabb".to_string()),
            custom_sni: Some("sni.example.com".to_string()),
            has_ipv6: false,
            skip_verification: true,
            certificate: None,
            upstream_protocol: Protocol::Http2,
            anti_dpi: false,
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
        };

        let ep = endpoint_from_deeplink_config(config).unwrap();
        assert_eq!(ep.client_random, "");
        assert_eq!(ep.custom_sni, "");
        assert_eq!(ep.upstream_protocol, "http3");
        assert!(ep.anti_dpi);
    }
}
