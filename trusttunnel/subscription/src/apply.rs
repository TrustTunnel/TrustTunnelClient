use trusttunnel_settings::composer::apply_endpoint_to_document;

use crate::{parse_endpoint_toml, SubscriptionError, SubscriptionResponse};

/// Merge the subscription document into the endpoint TOML fragment: rewrite
/// the live endpoint fields, stamp the fetch time, and preserve everything
/// the model does not represent — comments, key order, unknown keys.
pub fn apply_endpoint(
    endpoint_toml: &str,
    subscription_json: &str,
) -> Result<String, SubscriptionError> {
    apply_endpoint_at(endpoint_toml, subscription_json, &utc_now_rfc3339)
}

fn apply_endpoint_at(
    endpoint_toml: &str,
    subscription_json: &str,
    now: &dyn Fn() -> String,
) -> Result<String, SubscriptionError> {
    let response = SubscriptionResponse::from_json(subscription_json)?;
    // Parse both views up front; a broken or incomplete endpoint fails here
    // as an ordinary parse error.
    let mut endpoint = parse_endpoint_toml(endpoint_toml)?;
    let document = endpoint_toml
        .parse::<toml_edit::Document>()
        .map_err(|_| SubscriptionError::Other("Failed to parse endpoint document".into()))?;

    if endpoint.subscription.is_none() {
        return Err(SubscriptionError::NoSubscription);
    }

    response.apply_to(&mut endpoint);
    if let Some(subscription) = &mut endpoint.subscription {
        subscription.last_fetched_at = Some(now());
    }

    let document = apply_endpoint_to_document(document, &endpoint)
        .map_err(|e| SubscriptionError::Other(format!("Failed to compose endpoint: {e}")))?;
    Ok(document.to_string())
}

fn utc_now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{extract_endpoint, replace_endpoint};

    const ENDPOINT: &str = r#"
[endpoint]
hostname = "old.example.com"
addresses = ["1.1.1.1:443"]
username = "alice"
password = "old"
certificate = "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n"
# a comment that must survive
unknown_key_the_cpp_parser_reads = "keep me"

[endpoint.subscription]
url = "https://u:p@old.example.com/subscription"
"#;

    fn body() -> String {
        serde_json::json!({
            "version": 1,
            "hostname": "new.example.com",
            "address": "5.6.7.8:443",
            "username": "bob",
            "password": "hunter2",
            "has_ipv6": true,
            "upstream_protocol": "http3",
            "anti_dpi": false,
            "skip_verification": false
        })
        .to_string()
    }

    fn fixed_now() -> String {
        "2026-07-28T12:00:00Z".to_string()
    }

    #[test]
    fn apply_rewrites_live_fields_and_stamps_time() {
        let outcome = apply_endpoint_at(ENDPOINT, &body(), &fixed_now).unwrap();
        let doc: toml_edit::Document = outcome.parse().unwrap();
        assert_eq!(
            doc["endpoint"]["hostname"].as_str(),
            Some("new.example.com")
        );
        assert_eq!(
            doc["endpoint"]["addresses"]
                .as_array()
                .unwrap()
                .get(0)
                .and_then(|item| item.as_str()),
            Some("5.6.7.8:443")
        );
        assert_eq!(
            doc["endpoint"]["subscription"]["last_fetched_at"].as_str(),
            Some("2026-07-28T12:00:00Z")
        );
        assert_eq!(doc["endpoint"]["certificate"].as_str(), Some(""));
        assert!(outcome.contains("# a comment that must survive"));
        assert!(outcome.contains("unknown_key_the_cpp_parser_reads = \"keep me\""));
        assert!(outcome.contains("url = \"https://u:p@old.example.com/subscription\""));
    }

    #[test]
    fn apply_keeps_the_endpoint_scope() {
        let outcome = apply_endpoint_at(ENDPOINT, &body(), &fixed_now).unwrap();
        assert!(!outcome.contains("loglevel"), "unexpected: {outcome}");
        assert!(!outcome.contains("[listener]"), "unexpected: {outcome}");
    }

    #[test]
    fn missing_subscription_table_is_a_distinct_error() {
        let endpoint = ENDPOINT.replace(
            "[endpoint.subscription]\nurl = \"https://u:p@old.example.com/subscription\"\n",
            "",
        );
        let err = apply_endpoint_at(&endpoint, &body(), &fixed_now).unwrap_err();
        assert_eq!(err.to_string(), "No subscription URL configured.");
    }

    #[test]
    fn invalid_document_is_an_error() {
        let mut doc: serde_json::Value = serde_json::from_str(&body()).unwrap();
        doc["version"] = serde_json::json!(2);
        let err = apply_endpoint_at(ENDPOINT, &doc.to_string(), &fixed_now).unwrap_err();
        assert!(err.to_string().contains("upgrade"), "unexpected: {err}");
    }

    #[test]
    fn incomplete_endpoint_fails_as_parse_error() {
        let endpoint = "[endpoint]\n[endpoint.subscription]\nurl = \"https://u:p@h/s\"\n";
        let err = apply_endpoint_at(endpoint, &body(), &fixed_now).unwrap_err();
        assert!(
            err.to_string().contains("Failed to parse endpoint"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn parse_error_does_not_leak_credentials() {
        // The unterminated string puts the parse error on the URL line.
        let endpoint = ENDPOINT.replace(
            "url = \"https://u:p@old.example.com/subscription\"",
            "url = \"https://u:p@old.example.com/subscription",
        );
        let err = apply_endpoint_at(&endpoint, &body(), &fixed_now).unwrap_err();
        assert!(
            err.to_string().contains("Failed to parse endpoint"),
            "unexpected: {err}"
        );
        assert!(!err.to_string().contains("u:p@"), "unexpected: {err}");
    }

    #[test]
    fn extract_apply_replace_roundtrip_preserves_the_config() {
        let config = format!("# a top-level comment\nloglevel = \"info\"\n{ENDPOINT}\n[listener.socks]\naddress = \"127.0.0.1:1080\"\n");
        let fragment = extract_endpoint(&config).unwrap();
        let refreshed = apply_endpoint_at(&fragment, &body(), &fixed_now).unwrap();
        let updated = replace_endpoint(&config, &refreshed).unwrap();
        let doc: toml_edit::Document = updated.parse().unwrap();
        assert_eq!(
            doc["endpoint"]["hostname"].as_str(),
            Some("new.example.com")
        );
        assert!(updated.contains("# a top-level comment"));
        assert!(updated.contains("loglevel = \"info\""));
        assert!(updated.contains("[listener.socks]"));
        // Unknown keys of the endpoint ride through extract and apply.
        assert!(updated.contains("unknown_key_the_cpp_parser_reads = \"keep me\""));
    }
}
