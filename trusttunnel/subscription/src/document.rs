//! Whole-config document plumbing for the refresh flow: extracting the
//! `[endpoint]` subtree from a config and replacing it with a refreshed
//! fragment. These functions know nothing about subscriptions — they only
//! move TOML subtrees around, preserving everything they do not touch.

use crate::SubscriptionError;

/// Extract the `[endpoint]` subtree of the config as a standalone TOML
/// document. The subtree keeps its comments and unknown keys.
pub fn extract_endpoint(config_text: &str) -> Result<String, SubscriptionError> {
    let document = config_text
        .parse::<toml_edit::Document>()
        .map_err(|_| SubscriptionError::Other("Failed to parse config document".into()))?;
    let endpoint = document
        .get("endpoint")
        .cloned()
        .ok_or_else(|| SubscriptionError::Other("Missing [endpoint] table in the config".into()))?;
    let mut fragment = toml_edit::Document::new();
    fragment["endpoint"] = endpoint;
    Ok(fragment.to_string())
}

/// Replace the config's `[endpoint]` subtree with the one from the endpoint
/// fragment, preserving everything else in the config — comments, key order,
/// unknown keys. Top-level keys of the fragment other than `endpoint` are
/// ignored.
pub fn replace_endpoint(
    config_text: &str,
    endpoint_toml: &str,
) -> Result<String, SubscriptionError> {
    let mut document = config_text
        .parse::<toml_edit::Document>()
        .map_err(|_| SubscriptionError::Other("Failed to parse config document".into()))?;
    let fragment = endpoint_toml
        .parse::<toml_edit::Document>()
        .map_err(|_| SubscriptionError::Other("Failed to parse endpoint document".into()))?;
    let endpoint = fragment.get("endpoint").cloned().ok_or_else(|| {
        SubscriptionError::Other("Missing [endpoint] table in the endpoint document".into())
    })?;
    document["endpoint"] = endpoint;
    Ok(document.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
# a comment that must survive
loglevel = "info"

[endpoint]
hostname = "old.example.com"
addresses = ["1.1.1.1:443"]
username = "alice"
password = "old"
unknown_key_the_cpp_parser_reads = "keep me"

[endpoint.subscription]
url = "https://u:p@old.example.com/subscription"

[listener.socks]
address = "127.0.0.1:1080"
"#;

    const ENDPOINT: &str = r#"[endpoint]
hostname = "new.example.com"
addresses = ["5.6.7.8:443"]
username = "bob"
password = "hunter2"

[endpoint.subscription]
url = "https://u:p@old.example.com/subscription"
last_fetched_at = "2026-07-28T12:00:00Z"
"#;

    #[test]
    fn extract_returns_the_endpoint_subtree_with_its_comments() {
        let fragment = extract_endpoint(CONFIG).unwrap();
        let doc: toml_edit::Document = fragment.parse().unwrap();
        assert_eq!(
            doc["endpoint"]["hostname"].as_str(),
            Some("old.example.com")
        );
        assert_eq!(
            doc["endpoint"]["subscription"]["url"].as_str(),
            Some("https://u:p@old.example.com/subscription")
        );
        assert!(fragment.contains("unknown_key_the_cpp_parser_reads = \"keep me\""));
        assert!(!fragment.contains("listener"), "unexpected: {fragment}");
    }

    #[test]
    fn extract_without_endpoint_table_is_an_error() {
        let err = extract_endpoint("loglevel = \"info\"\n").unwrap_err();
        assert!(err.to_string().contains("[endpoint]"), "unexpected: {err}");
    }

    #[test]
    fn extract_with_invalid_config_is_a_parse_error() {
        let err = extract_endpoint("not [valid toml").unwrap_err();
        assert!(
            err.to_string().contains("Failed to parse config"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn replace_swaps_the_endpoint_and_preserves_the_rest() {
        let updated = replace_endpoint(CONFIG, ENDPOINT).unwrap();
        let doc: toml_edit::Document = updated.parse().unwrap();
        assert_eq!(
            doc["endpoint"]["hostname"].as_str(),
            Some("new.example.com")
        );
        assert_eq!(
            doc["endpoint"]["subscription"]["last_fetched_at"].as_str(),
            Some("2026-07-28T12:00:00Z")
        );
        assert!(updated.contains("# a comment that must survive"));
        assert!(updated.contains("[listener.socks]"));
        assert!(updated.contains("address = \"127.0.0.1:1080\""));
        // The refreshed fragment replaced the old subtree wholesale.
        assert!(!updated.contains("unknown_key_the_cpp_parser_reads"));
    }

    #[test]
    fn replace_ignores_fragment_keys_outside_the_endpoint() {
        let fragment = format!("loglevel = \"debug\"\n{ENDPOINT}");
        let updated = replace_endpoint(CONFIG, &fragment).unwrap();
        assert!(
            updated.contains("loglevel = \"info\""),
            "unexpected: {updated}"
        );
        assert!(updated.contains("hostname = \"new.example.com\""));
    }

    #[test]
    fn replace_without_endpoint_in_the_fragment_is_an_error() {
        let err = replace_endpoint(CONFIG, "loglevel = \"debug\"\n").unwrap_err();
        assert!(err.to_string().contains("[endpoint]"), "unexpected: {err}");
    }

    #[test]
    fn replace_with_invalid_fragment_is_a_parse_error() {
        let err = replace_endpoint(CONFIG, "not [valid toml").unwrap_err();
        assert!(
            err.to_string().contains("Failed to parse endpoint"),
            "unexpected: {err}"
        );
        assert!(!err.to_string().contains("alice"), "unexpected: {err}");
    }
}
