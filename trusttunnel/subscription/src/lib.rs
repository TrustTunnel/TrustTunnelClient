//! Client-side support for TrustTunnel endpoint subscriptions.

mod apply;
mod document;
mod fetch;
mod response;
mod write;

use trusttunnel_settings::Endpoint;

pub use apply::apply_endpoint;
pub use document::{extract_endpoint, replace_endpoint};
pub use fetch::{
    fetch_for_endpoint, fetch_subscription, fetch_subscription_json, HttpError, HttpRequest,
    HttpTransport, UreqTransport,
};
pub use response::SubscriptionResponse;
pub use write::replace_file_atomic;

#[derive(serde::Deserialize)]
struct EndpointSection {
    endpoint: Endpoint,
}

/// Parse an endpoint TOML fragment — a document with an `[endpoint]` table —
/// into the endpoint model. The parse error details are dropped on purpose:
/// they quote the offending line, which may carry credentials.
pub(crate) fn parse_endpoint_toml(endpoint_toml: &str) -> Result<Endpoint, SubscriptionError> {
    toml::from_str::<EndpointSection>(endpoint_toml)
        .map(|section| section.endpoint)
        .map_err(|_| SubscriptionError::Other("Failed to parse endpoint settings".into()))
}

#[derive(Debug)]
pub enum SubscriptionError {
    NoSubscription,
    InvalidDocument(String),
    Other(String),
}

impl std::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionError::NoSubscription => {
                write!(f, "No subscription URL configured.")
            }
            SubscriptionError::InvalidDocument(reason) => {
                write!(f, "Invalid subscription document: {reason}")
            }
            SubscriptionError::Other(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SubscriptionError {}
