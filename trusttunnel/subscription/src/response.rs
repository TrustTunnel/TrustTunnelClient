use serde::Deserialize;
use trusttunnel_settings::Endpoint;

use crate::SubscriptionError;

const SUPPORTED_VERSION: u64 = 1;

const KNOWN_PROTOCOLS: [&str; 2] = ["http2", "http3"];

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SubscriptionResponse {
    pub version: u64,
    pub hostname: String,
    pub address: String,
    pub username: String,
    pub password: String,
    pub has_ipv6: bool,
    pub upstream_protocol: String,
    pub anti_dpi: bool,
    pub skip_verification: bool,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub custom_sni: Option<String>,
    #[serde(default)]
    pub client_random_prefix: Option<String>,
    #[serde(default)]
    pub client_random_auth_key: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub dns_upstreams: Option<Vec<String>>,
}

impl SubscriptionResponse {
    /// Parse and fully validate a response body.
    pub fn from_json(body: &str) -> Result<Self, SubscriptionError> {
        let response: SubscriptionResponse = serde_json::from_str(body).map_err(|e| {
            SubscriptionError::InvalidDocument(format!("not a valid subscription document: {e}"))
        })?;
        response.validate()?;
        Ok(response)
    }

    /// Overlay the subscription-owned fields of `endpoint` from this response.
    /// `name`, `dns_upstreams` and `subscription` are left untouched; an
    /// optional field omitted from the response resets to its default.
    pub fn apply_to(&self, endpoint: &mut Endpoint) {
        endpoint.hostname = self.hostname.clone();
        endpoint.addresses = vec![self.address.clone()];
        endpoint.username = self.username.clone();
        endpoint.password = self.password.clone();
        endpoint.has_ipv6 = self.has_ipv6;
        endpoint.upstream_protocol = self.upstream_protocol.clone();
        endpoint.anti_dpi = self.anti_dpi;
        endpoint.skip_verification = self.skip_verification;
        endpoint.certificate = self.certificate.clone();
        endpoint.custom_sni = self.custom_sni.clone().unwrap_or_default();
        endpoint.client_random = self.client_random_prefix.clone().unwrap_or_default();
        endpoint.client_random_auth_key = self.client_random_auth_key.clone().unwrap_or_default();
    }

    fn validate(&self) -> Result<(), SubscriptionError> {
        if self.version > SUPPORTED_VERSION {
            return Err(SubscriptionError::InvalidDocument(format!(
                "unsupported version {}; please upgrade trusttunnel_client",
                self.version
            )));
        }
        for (field, value) in [
            ("hostname", &self.hostname),
            ("address", &self.address),
            ("username", &self.username),
            ("password", &self.password),
        ] {
            if value.is_empty() {
                return Err(SubscriptionError::InvalidDocument(format!(
                    "required field '{field}' is missing or empty"
                )));
            }
        }
        if !KNOWN_PROTOCOLS.contains(&self.upstream_protocol.as_str()) {
            return Err(SubscriptionError::InvalidDocument(format!(
                "unrecognized upstream_protocol '{}'",
                self.upstream_protocol
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use trusttunnel_settings::Endpoint;

    use super::*;

    fn valid_document() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "hostname": "vpn.example.com",
            "address": "1.2.3.4:443",
            "username": "alice",
            "password": "s3cr3t",
            "has_ipv6": true,
            "upstream_protocol": "http2",
            "anti_dpi": false,
            "skip_verification": false
        })
    }

    #[test]
    fn parses_minimal_valid_document() {
        let response = SubscriptionResponse::from_json(&valid_document().to_string()).unwrap();
        assert_eq!(response.hostname, "vpn.example.com");
        assert_eq!(response.address, "1.2.3.4:443");
        assert!(response.certificate.is_none());
        assert!(response.client_random_prefix.is_none());
        assert!(response.client_random_auth_key.is_none());
        assert!(response.name.is_none());
        assert!(response.dns_upstreams.is_none());
    }

    #[test]
    fn rejects_newer_version_with_upgrade_message() {
        let mut doc = valid_document();
        doc["version"] = serde_json::json!(2);
        let err = SubscriptionResponse::from_json(&doc.to_string()).unwrap_err();
        assert!(err.to_string().contains("upgrade"), "unexpected: {err}");
    }

    #[test]
    fn rejects_missing_version() {
        let mut doc = valid_document();
        doc.as_object_mut().unwrap().remove("version");
        assert!(SubscriptionResponse::from_json(&doc.to_string()).is_err());
    }

    #[test]
    fn rejects_empty_required_field() {
        let mut doc = valid_document();
        doc["password"] = serde_json::json!("");
        let err = SubscriptionResponse::from_json(&doc.to_string()).unwrap_err();
        assert!(err.to_string().contains("password"), "unexpected: {err}");
    }

    #[test]
    fn rejects_unknown_upstream_protocol() {
        let mut doc = valid_document();
        doc["upstream_protocol"] = serde_json::json!("http9");
        let err = SubscriptionResponse::from_json(&doc.to_string()).unwrap_err();
        assert!(
            err.to_string().contains("upstream_protocol"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn ignores_unrecognized_fields() {
        let mut doc = valid_document();
        doc["future_field"] = serde_json::json!({"anything": true});
        assert!(SubscriptionResponse::from_json(&doc.to_string()).is_ok());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(SubscriptionResponse::from_json("{not json").is_err());
    }

    #[test]
    fn rejects_non_object_json() {
        assert!(SubscriptionResponse::from_json("[1,2,3]").is_err());
    }

    fn response() -> SubscriptionResponse {
        SubscriptionResponse::from_json(
            &serde_json::json!({
                "version": 1,
                "hostname": "new.example.com",
                "address": "5.6.7.8:443",
                "username": "bob",
                "password": "hunter2",
                "has_ipv6": false,
                "upstream_protocol": "http3",
                "anti_dpi": true,
                "skip_verification": true,
                "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
                "custom_sni": "sni.example.com",
                "client_random_prefix": "aabb/16",
                "name": "Ignored Name",
                "dns_upstreams": ["tls://9.9.9.9"]
            })
            .to_string(),
        )
        .unwrap()
    }

    fn auth_key_response() -> SubscriptionResponse {
        let mut doc = valid_document();
        doc["client_random_auth_key"] = serde_json::json!("00112233445566778899aabbccddeeff");
        SubscriptionResponse::from_json(&doc.to_string()).unwrap()
    }

    fn endpoint() -> Endpoint {
        Endpoint {
            hostname: "old.example.com".to_string(),
            addresses: vec!["1.1.1.1:443".to_string(), "2.2.2.2:443".to_string()],
            name: Some("My VPN".to_string()),
            dns_upstreams: vec!["tls://1.1.1.1".to_string()],
            ..Endpoint::default()
        }
    }

    #[test]
    fn overlays_all_live_fields() {
        let mut ep = endpoint();
        ep.client_random_auth_key = "deadbeef".to_string();
        response().apply_to(&mut ep);
        assert_eq!(ep.hostname, "new.example.com");
        assert_eq!(ep.addresses, vec!["5.6.7.8:443".to_string()]);
        assert_eq!(ep.username, "bob");
        assert_eq!(ep.password, "hunter2");
        assert!(!ep.has_ipv6);
        assert_eq!(ep.upstream_protocol, "http3");
        assert!(ep.anti_dpi);
        assert!(ep.skip_verification);
        assert_eq!(
            ep.certificate.as_deref(),
            Some("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n")
        );
        assert_eq!(ep.custom_sni, "sni.example.com");
        assert_eq!(ep.client_random, "aabb/16");
        assert_eq!(ep.client_random_auth_key, "");
    }

    #[test]
    fn applies_auth_key_and_clears_prefix() {
        let mut ep = endpoint();
        ep.client_random = "ff/8".to_string();
        auth_key_response().apply_to(&mut ep);
        assert_eq!(ep.client_random, "");
        assert_eq!(
            ep.client_random_auth_key,
            "00112233445566778899aabbccddeeff"
        );
    }

    #[test]
    fn replaces_addresses_wholesale() {
        let mut ep = endpoint();
        response().apply_to(&mut ep);
        assert_eq!(ep.addresses.len(), 1);
    }

    #[test]
    fn leaves_creation_only_fields_untouched() {
        let mut ep = endpoint();
        response().apply_to(&mut ep);
        assert_eq!(ep.name.as_deref(), Some("My VPN"));
        assert_eq!(ep.dns_upstreams, vec!["tls://1.1.1.1".to_string()]);
        assert!(ep.subscription.is_none());
    }

    #[test]
    fn omitted_optionals_reset_to_default() {
        let body = serde_json::json!({
            "version": 1,
            "hostname": "new.example.com",
            "address": "5.6.7.8:443",
            "username": "bob",
            "password": "hunter2",
            "has_ipv6": true,
            "upstream_protocol": "http2",
            "anti_dpi": false,
            "skip_verification": false
        });
        let response = SubscriptionResponse::from_json(&body.to_string()).unwrap();
        let mut ep = Endpoint {
            certificate: Some("pinned".to_string()),
            custom_sni: "old-sni".to_string(),
            client_random: "ff/8".to_string(),
            client_random_auth_key: "deadbeef".to_string(),
            ..endpoint()
        };
        response.apply_to(&mut ep);
        assert!(ep.certificate.is_none(), "stale pin must be dropped");
        assert_eq!(ep.custom_sni, "");
        assert_eq!(ep.client_random, "");
        assert_eq!(ep.client_random_auth_key, "");
    }
}
