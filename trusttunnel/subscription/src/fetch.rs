use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;

use crate::{SubscriptionError, SubscriptionResponse};

const MAX_BODY_BYTES: usize = 1024 * 1024;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: u32 = 5;

pub struct HttpRequest<'a> {
    pub url: &'a str,
    pub pinned_certificate_pem: Option<&'a str>,
    pub skip_verification: bool,
    /// Fixed `host:port` to connect to instead of resolving the URL's host.
    /// The TLS SNI and the HTTP Host header still carry the URL host.
    pub connect_address: Option<&'a str>,
}

impl<'a> HttpRequest<'a> {
    /// Build a request for fetching `url` on behalf of `endpoint`.
    ///
    /// Pins the certificate and forces DNS resolution to the first address of the endpoint
    /// if the certificate is set for the endpoint to allow secure request to a subscription URL
    /// host with self-signed certificate and non-resolvable domain (the same logic as for tunnel connection)
    pub fn for_endpoint(url: &'a str, endpoint: &'a trusttunnel_settings::Endpoint) -> Self {
        let certificate = endpoint
            .certificate
            .as_deref()
            .filter(|certificate| !certificate.is_empty());
        let host_matches = url::Url::parse(url)
            .ok()
            .and_then(|parsed| {
                parsed
                    .host_str()
                    .map(|host| host.eq_ignore_ascii_case(&endpoint.hostname))
            })
            .unwrap_or(false);
        let reuse_endpoint = host_matches && (certificate.is_some() || endpoint.skip_verification);
        HttpRequest {
            url,
            pinned_certificate_pem: if reuse_endpoint { certificate } else { None },
            skip_verification: reuse_endpoint && endpoint.skip_verification,
            connect_address: if reuse_endpoint {
                endpoint.addresses.first().map(String::as_str)
            } else {
                None
            },
        }
    }
}

/// Gate the pin by host: when `certificate_host` is `Some`, the certificate
/// applies only if the URL's host matches it; when `None`, it always applies.
fn pinned_certificate<'a>(
    url: &str,
    certificate_host: Option<&str>,
    certificate: Option<&'a str>,
) -> Option<&'a str> {
    let applies = match certificate_host {
        Some(expected) => url::Url::parse(url)
            .ok()
            .and_then(|parsed| {
                parsed
                    .host_str()
                    .map(|host| host.eq_ignore_ascii_case(expected))
            })
            .unwrap_or(false),
        None => true,
    };
    if applies {
        certificate
    } else {
        None
    }
}

#[derive(Debug)]
pub enum HttpError {
    NotHttps,
    BadUrl,
    BadRedirect,
    HttpStatus(u16),
    BodyTooLarge,
    Tls,
    BadPinnedCertificate,
    Transport(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::NotHttps => write!(f, "URL must use the https scheme"),
            HttpError::BadUrl => write!(f, "URL could not be parsed"),
            HttpError::BadRedirect => {
                write!(f, "redirected to a non-https or too deep target")
            }
            HttpError::HttpStatus(401) => {
                write!(f, "server rejected the embedded credentials (401)")
            }
            HttpError::HttpStatus(403) => write!(f, "disabled on the server (403)"),
            HttpError::HttpStatus(404) => write!(f, "document not found on the server (404)"),
            HttpError::HttpStatus(code) => write!(f, "server answered HTTP status {code}"),
            HttpError::BodyTooLarge => write!(f, "response exceeded 1 MiB"),
            HttpError::Tls => write!(f, "server certificate verification failed"),
            HttpError::BadPinnedCertificate => {
                write!(f, "the pinned certificate could not be parsed")
            }
            HttpError::Transport(message) => write!(f, "request failed: {message}"),
        }
    }
}

impl std::error::Error for HttpError {}

pub trait HttpTransport {
    fn get(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpError>;
}

fn fetch_body(
    request: &HttpRequest,
    transport: &dyn HttpTransport,
) -> Result<String, SubscriptionError> {
    if request.skip_verification {
        // Warn on every unverified fetch; never log the URL.
        eprintln!("WARNING: fetching the subscription without verifying the server certificate");
    }
    let body = transport
        .get(request)
        .map_err(|e| SubscriptionError::Other(format!("Failed to fetch the subscription: {e}")))?;
    String::from_utf8(body)
        .map_err(|_| SubscriptionError::InvalidDocument("response is not valid UTF-8".into()))
}

/// Fetch and validate the subscription document for one request.
pub fn fetch_subscription(
    request: &HttpRequest,
    transport: &dyn HttpTransport,
) -> Result<SubscriptionResponse, SubscriptionError> {
    SubscriptionResponse::from_json(&fetch_body(request, transport)?)
}

/// Fetch the subscription document at `url` and return the raw validated
/// body. `certificate_host` gates the pin: when `Some`, the certificate is
/// only used if the URL's host matches it; when `None`, it is always used.
pub fn fetch_subscription_json(
    url: &str,
    certificate_host: Option<&str>,
    certificate: Option<&str>,
    skip_verification: bool,
    transport: &dyn HttpTransport,
) -> Result<String, SubscriptionError> {
    let request = HttpRequest {
        url,
        pinned_certificate_pem: pinned_certificate(url, certificate_host, certificate),
        skip_verification,
        connect_address: None,
    };
    let body = fetch_body(&request, transport)?;
    SubscriptionResponse::from_json(&body)?;
    Ok(body)
}

/// Fetch the subscription document for the endpoint described by the config
/// text and return the raw validated body. The subscription URL and the TLS
/// parameters reuse policy are read from the endpoint section of the config
/// (see [`HttpRequest::for_endpoint`]).
pub fn fetch_for_config(
    config_text: &str,
    transport: &dyn HttpTransport,
) -> Result<String, SubscriptionError> {
    let settings: trusttunnel_settings::Settings = toml::from_str(config_text)
        .map_err(|_| SubscriptionError::Other("Failed to parse config".into()))?;
    let subscription = settings
        .endpoint
        .subscription
        .as_ref()
        .filter(|subscription| !subscription.url.is_empty())
        .ok_or(SubscriptionError::NoSubscription)?;
    let request = HttpRequest::for_endpoint(&subscription.url, &settings.endpoint);
    let body = fetch_body(&request, transport)?;
    SubscriptionResponse::from_json(&body)?;
    Ok(body)
}

struct PreparedRequest {
    url: String,
    authorization: Option<String>,
}

fn validate_url(url: &str) -> Result<url::Url, HttpError> {
    let parsed = url::Url::parse(url).map_err(|_| HttpError::BadUrl)?;
    if parsed.scheme() != "https" {
        return Err(HttpError::NotHttps);
    }
    Ok(parsed)
}

fn prepare_request(url: &str) -> Result<PreparedRequest, HttpError> {
    let mut parsed = validate_url(url)?;
    let authorization = if parsed.username().is_empty() {
        None
    } else {
        let decode = |raw: &str| {
            percent_encoding::percent_decode_str(raw)
                .decode_utf8()
                .map(|cow| cow.into_owned())
                .map_err(|_| HttpError::BadUrl)
        };
        let username = decode(parsed.username())?;
        let password = decode(parsed.password().unwrap_or_default())?;
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        parsed.set_username("").map_err(|_| HttpError::BadUrl)?;
        parsed.set_password(None).map_err(|_| HttpError::BadUrl)?;
        Some(format!("Basic {credentials}"))
    };
    Ok(PreparedRequest {
        url: parsed.into(),
        authorization,
    })
}

fn redirect_target(current: &str, location: &str) -> Result<String, HttpError> {
    let base = url::Url::parse(current).map_err(|_| HttpError::BadUrl)?;
    let target = base.join(location).map_err(|_| HttpError::BadRedirect)?;
    if target.scheme() != "https" {
        return Err(HttpError::BadRedirect);
    }
    Ok(target.into())
}

/// Extract the lowercase `host:port` netloc of an https URL.
fn netloc(url: &str) -> Result<String, HttpError> {
    let parsed = validate_url(url)?;
    let host = parsed.host_str().ok_or(HttpError::BadUrl)?;
    let port = parsed.port_or_known_default().ok_or(HttpError::BadUrl)?;
    Ok(format!("{}:{}", host.to_ascii_lowercase(), port))
}

// Credentials are only ever sent to the original host.
fn apply_redirect(prepared: &mut PreparedRequest, location: &str) -> Result<(), HttpError> {
    let target = redirect_target(&prepared.url, location)?;
    let same_host = url::Url::parse(&prepared.url)
        .ok()
        .zip(url::Url::parse(&target).ok())
        .map(|(current, next)| {
            current.host_str() == next.host_str()
                && current.port_or_known_default() == next.port_or_known_default()
        })
        .unwrap_or(false);
    if !same_host {
        prepared.authorization = None;
    }
    prepared.url = target;
    Ok(())
}

fn read_bounded(reader: &mut impl Read) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    let mut limited = reader.take((MAX_BODY_BYTES + 1) as u64);
    limited
        .read_to_end(&mut body)
        .map_err(|e| HttpError::Transport(e.to_string()))?;
    if body.len() > MAX_BODY_BYTES {
        return Err(HttpError::BodyTooLarge);
    }
    Ok(body)
}

fn status_error(code: u16) -> HttpError {
    HttpError::HttpStatus(code)
}

/// Answer the subscription URL's netloc with the endpoint's fixed address,
/// never touching DNS for it; resolve any other netloc (e.g. a redirect
/// target) via the system DNS.
struct PinnedAddressResolver {
    /// Netloc (`host:port`) of the subscription URL.
    netloc: String,
    /// Socket addresses the endpoint's first address resolved to.
    addresses: Vec<SocketAddr>,
}

impl PinnedAddressResolver {
    fn new(url: &str, connect_address: &str) -> Result<Self, HttpError> {
        let parsed = validate_url(url)?;
        let host = parsed.host_str().ok_or(HttpError::BadUrl)?;
        let port = parsed.port_or_known_default().ok_or(HttpError::BadUrl)?;
        // `ToSocketAddrs` accepts both `ip:port` and `hostname:port` — the
        // endpoint's own address may legitimately be a hostname.
        let addresses: Vec<SocketAddr> = connect_address
            .to_socket_addrs()
            .map_err(|e| HttpError::Transport(format!("endpoint address is unusable: {e}")))?
            .collect();
        if addresses.is_empty() {
            return Err(HttpError::Transport(
                "endpoint address is unusable".to_string(),
            ));
        }
        Ok(Self {
            netloc: format!("{host}:{port}"),
            addresses,
        })
    }
}

impl ureq::Resolver for PinnedAddressResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        if netloc.eq_ignore_ascii_case(&self.netloc) {
            return Ok(self.addresses.clone());
        }
        ToSocketAddrs::to_socket_addrs(netloc).map(|iter| iter.collect())
    }
}

fn parse_pem_certificates(pem: &str) -> Vec<rustls::Certificate> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .map(|certs| certs.into_iter().map(rustls::Certificate).collect())
        .unwrap_or_default()
}

pub struct UreqTransport;

impl UreqTransport {
    /// Build the trust store. A pinned certificate is the exclusive trust
    /// anchor, mirroring the tunnel connection's custom CA store: public
    /// WebPKI roots are only used when no pin is set, and an unparsable pin
    /// is an error rather than a silent fallback.
    fn root_store(
        pinned_certificate_pem: Option<&str>,
    ) -> Result<rustls::RootCertStore, HttpError> {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(pem) = pinned_certificate_pem {
            let (added, _) = roots.add_parsable_certificates(&parse_pem_certificates(pem));
            if added == 0 {
                return Err(HttpError::BadPinnedCertificate);
            }
        } else {
            roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
        }
        Ok(roots)
    }

    fn build_tls_config(
        pinned_certificate_pem: Option<&str>,
        skip_verification: bool,
    ) -> Result<rustls::ClientConfig, HttpError> {
        if skip_verification {
            return Ok(rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(NoVerification))
                .with_no_client_auth());
        }
        Ok(rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(Self::root_store(pinned_certificate_pem)?)
            .with_no_client_auth())
    }

    /// Build an agent carrying the request's TLS and addressing policy.
    fn build_policy_agent(request: &HttpRequest) -> Result<ureq::Agent, HttpError> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout(OPERATION_TIMEOUT)
            .redirects(0)
            .tls_config(Arc::new(Self::build_tls_config(
                request.pinned_certificate_pem,
                request.skip_verification,
            )?));
        if let Some(connect_address) = request.connect_address {
            builder = builder.resolver(PinnedAddressResolver::new(request.url, connect_address)?);
        }
        Ok(builder.build())
    }

    /// Build an agent with the default policy: public roots, verification
    /// on, system DNS.
    fn build_default_agent() -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout(OPERATION_TIMEOUT)
            .redirects(0)
            .tls_config(Arc::new(
                Self::build_tls_config(None, false).expect("default TLS config"),
            ))
            .build()
    }

    fn fetch_once(
        agent: &ureq::Agent,
        prepared: &PreparedRequest,
    ) -> Result<ureq::Response, HttpError> {
        let mut call = agent.get(&prepared.url);
        if let Some(header) = &prepared.authorization {
            call = call.set("Authorization", header);
        }
        match call.call() {
            Ok(response) => Ok(response),
            Err(ureq::Error::Status(code, _)) => Err(status_error(code)),
            Err(ureq::Error::Transport(transport)) => {
                let message = transport.to_string();
                if message.contains("certificate") || message.contains("tls") {
                    return Err(HttpError::Tls);
                }
                // ureq's raw message can embed the host or address.
                Err(HttpError::Transport(match transport.kind() {
                    ureq::ErrorKind::Dns => "DNS resolution failed".to_string(),
                    ureq::ErrorKind::ConnectionFailed => "connection failed".to_string(),
                    _ => "transport error".to_string(),
                }))
            }
        }
    }
}

impl HttpTransport for UreqTransport {
    fn get(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpError> {
        // The request's TLS and addressing policy applies only to the
        // original netloc; a redirect to another netloc is fetched with the
        // default policy, so neither `skip_verification` nor the pin can
        // leak to a foreign host.
        let policy_netloc = netloc(request.url)?;
        let policy_agent = Self::build_policy_agent(request)?;
        let mut default_agent = None;
        let mut prepared = prepare_request(request.url)?;
        for _ in 0..=MAX_REDIRECTS {
            let agent = if netloc(&prepared.url)? == policy_netloc {
                &policy_agent
            } else {
                default_agent.get_or_insert_with(Self::build_default_agent)
            };
            let response = Self::fetch_once(agent, &prepared)?;
            if response.status() < 300 || response.status() >= 400 {
                return read_bounded(&mut response.into_reader());
            }
            let location = response
                .header("location")
                .ok_or(HttpError::BadRedirect)?
                .to_string();
            apply_redirect(&mut prepared, &location)?;
        }
        Err(HttpError::BadRedirect)
    }
}

struct NoVerification;

impl rustls::client::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_scheme() {
        let err = validate_url("http://example.com/subscription").unwrap_err();
        assert!(err.to_string().contains("https"), "unexpected: {err}");
    }

    #[test]
    fn extracts_percent_decoded_basic_auth() {
        let prepared = prepare_request("https://user%40corp:p%40ss@example.com/s").unwrap();
        assert_eq!(
            prepared.authorization.as_deref(),
            Some("Basic dXNlckBjb3JwOnBAc3M=") // base64("user@corp:p@ss")
        );
        assert_eq!(prepared.url, "https://example.com/s");
    }

    #[test]
    fn leaves_url_without_userinfo_untouched() {
        let prepared = prepare_request("https://example.com/s").unwrap();
        assert!(prepared.authorization.is_none());
        assert_eq!(prepared.url, "https://example.com/s");
    }

    #[test]
    fn redirect_to_http_is_rejected() {
        let target = redirect_target("https://example.com/a", "http://example.com/b").unwrap_err();
        assert!(target.to_string().contains("https"), "unexpected: {target}");
    }

    #[test]
    fn relative_redirect_resolves_against_origin() {
        let target = redirect_target("https://example.com/a/b", "../c").unwrap();
        assert_eq!(target, "https://example.com/c");
    }

    #[test]
    fn same_host_redirect_keeps_credentials() {
        let mut prepared = prepare_request("https://user:pass@example.com/s").unwrap();
        apply_redirect(&mut prepared, "/moved").unwrap();
        assert_eq!(prepared.url, "https://example.com/moved");
        assert!(prepared.authorization.is_some());
    }

    #[test]
    fn cross_host_redirect_drops_credentials() {
        let mut prepared = prepare_request("https://user:pass@example.com/s").unwrap();
        apply_redirect(&mut prepared, "https://other.example.net/s").unwrap();
        assert_eq!(prepared.url, "https://other.example.net/s");
        assert!(prepared.authorization.is_none());
    }

    #[test]
    fn body_limit_rejects_oversized_content() {
        let data = vec![0u8; MAX_BODY_BYTES + 1];
        let mut cursor = std::io::Cursor::new(data);
        assert!(read_bounded(&mut cursor).is_err());
    }

    #[test]
    fn body_limit_accepts_exact_boundary() {
        let data = vec![0u8; MAX_BODY_BYTES];
        let mut cursor = std::io::Cursor::new(data);
        assert_eq!(read_bounded(&mut cursor).unwrap().len(), MAX_BODY_BYTES);
    }

    #[test]
    fn maps_distinct_http_statuses() {
        assert!(matches!(status_error(401), HttpError::HttpStatus(401)));
        assert!(matches!(status_error(403), HttpError::HttpStatus(403)));
        assert!(matches!(status_error(404), HttpError::HttpStatus(404)));
        assert!(matches!(status_error(503), HttpError::HttpStatus(503)));
    }

    #[test]
    fn pinned_certificate_parses_as_der() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let certs = parse_pem_certificates(pem);
        assert_eq!(certs.len(), 1);
    }

    // A real self-signed certificate; only its parsability matters here.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIICzTCCAbWgAwIBAgIUI5i58RaE7RDhpJW/t9j2UKj4yMAwDQYJKoZIhvcNAQEL\n\
        BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjEwMDUxODU1NDdaFw0yNjEwMDYxODU1\n\
        NDdaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
        AoIBAQCZouKsiNOCRoYxOBYXlHt9cQRgof6tM9n0onLrCOxWCrSsBIVYNziIDpGr\n\
        FDJIc+bo71hXLlmUawp+F5jVzkXkH+hhyOSkb00aQDnd0o1GZW4yi2XSKtDyFbpe\n\
        YWhAfNCyaHd6OKF8NltmWnHZbLxLfuGSkUOq7c2IyhfbgO3jB09AhtveBP4+GIHU\n\
        myfBI3d4hAP2pP84L5seHjZSe9sP/Re6cik/3nxTEAFR5LkSTd6wCUYd++ezd9ru\n\
        T5RrjWqk18jemsMqViOlpMMDz7xboOk5k7GAJbCFAncR3yS+x5HeTfuTFTOiH8t5\n\
        sbKZg32WCX24PufuSCReJ9UZt1ndAgMBAAGjITAfMB0GA1UdDgQWBBRoCQIn3GGR\n\
        dT7yykti8S/mz8vCjTANBgkqhkiG9w0BAQsFAAOCAQEAHzb4YoKIxaNHLHQMYGj0\n\
        9O52KlKPTNnrGcJJ2La06ZTwVl/ob7sCU4LSduYQ80hwjQehSLaiYT+eUByk+ZyZ\n\
        1JcZWBCe0/EiSDyabEpyV9mbQno/bnw5Ih9qlmGLQg5BQBg/rogSYUL01JLM8k2p\n\
        vHQo0Vo+hwJk2G66UgcHSVw/nSdX/Og0EvdvigATQ5jBc61jjXxukzQ3fNHjX/Oj\n\
        5IgWD4pka+J8XIlczIxpRwyzLbXOahGeejusUibMcwt/ASo4l7HFDinvdPBQ1swS\n\
        2WtNQ80ad3te7ohKHOst4+vvdkW3O6E5Jslch5OiW9czn1NNcMHLwNC3Bpkt7HuH\n\
        zg==\n\
        -----END CERTIFICATE-----\n";

    #[test]
    fn valid_pin_is_the_only_trust_anchor() {
        let store = UreqTransport::root_store(Some(TEST_CERT_PEM)).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn unparsable_pin_is_an_error_not_a_fallback_to_public_roots() {
        let err = UreqTransport::root_store(Some("not a certificate")).unwrap_err();
        assert!(matches!(err, HttpError::BadPinnedCertificate));
        assert!(err.to_string().contains("pinned certificate"));
    }

    #[test]
    fn public_roots_are_used_without_a_pin() {
        let store = UreqTransport::root_store(None).unwrap();
        assert!(store.len() > 1);
    }

    #[test]
    fn policy_netloc_ignores_host_case_and_default_port() {
        assert_eq!(
            netloc("https://vpn.example.com/s").unwrap(),
            netloc("https://VPN.example.COM:443/other").unwrap()
        );
    }

    #[test]
    fn policy_netloc_treats_other_port_and_host_as_foreign() {
        let original = netloc("https://vpn.example.com/s").unwrap();
        assert_ne!(netloc("https://vpn.example.com:444/x").unwrap(), original);
        assert_ne!(netloc("https://other.example.net/x").unwrap(), original);
    }

    struct FakeTransport(Result<Vec<u8>, HttpError>);

    impl HttpTransport for FakeTransport {
        fn get(&self, _request: &HttpRequest) -> Result<Vec<u8>, HttpError> {
            match &self.0 {
                Ok(body) => Ok(body.clone()),
                Err(_) => Err(HttpError::Transport("simulated outage".to_string())),
            }
        }
    }

    fn valid_body() -> Vec<u8> {
        serde_json::json!({
            "version": 1,
            "hostname": "vpn.example.com",
            "address": "5.6.7.8:443",
            "username": "bob",
            "password": "hunter2",
            "has_ipv6": true,
            "upstream_protocol": "http3",
            "anti_dpi": false,
            "skip_verification": false
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn pin_applies_to_matching_host() {
        let pin = pinned_certificate(
            "https://vpn.example.com/s",
            Some("vpn.example.com"),
            Some("PEM"),
        );
        assert_eq!(pin, Some("PEM"));
    }

    #[test]
    fn pin_dropped_for_other_host() {
        let pin = pinned_certificate(
            "https://other.example.net/s",
            Some("vpn.example.com"),
            Some("PEM"),
        );
        assert_eq!(pin, None);
    }

    #[test]
    fn pin_always_applies_without_host_constraint() {
        let pin = pinned_certificate("https://anything.example/s", None, Some("PEM"));
        assert_eq!(pin, Some("PEM"));
    }

    #[test]
    fn json_fetch_returns_raw_validated_body() {
        let body = fetch_subscription_json(
            "https://h/s",
            None,
            None,
            false,
            &FakeTransport(Ok(valid_body())),
        )
        .unwrap();
        assert_eq!(body, String::from_utf8(valid_body()).unwrap());
    }

    #[test]
    fn json_fetch_rejects_invalid_document() {
        let err = fetch_subscription_json(
            "https://h/s",
            None,
            None,
            false,
            &FakeTransport(Ok(b"{}".to_vec())),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Invalid subscription document"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn json_fetch_reports_transport_failure() {
        let err = fetch_subscription_json(
            "https://h/s",
            None,
            None,
            false,
            &FakeTransport(Err(HttpError::Transport("down".to_string()))),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Failed to fetch"),
            "unexpected: {err}"
        );
    }

    const FETCH_CONFIG: &str = r#"
[endpoint]
hostname = "vpn.example.com"
addresses = ["1.1.1.1:443"]
username = "alice"
password = "old"
certificate = "-----BEGIN CERTIFICATE-----\nPIN\n-----END CERTIFICATE-----\n"
skip_verification = true

[endpoint.subscription]
url = "https://u:p@vpn.example.com/subscription"
"#;

    #[derive(Default)]
    struct SeenRequest {
        url: String,
        pinned_certificate_pem: Option<String>,
        skip_verification: bool,
        connect_address: Option<String>,
    }

    struct RecordingTransport(std::cell::RefCell<Option<SeenRequest>>);

    impl HttpTransport for RecordingTransport {
        fn get(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpError> {
            *self.0.borrow_mut() = Some(SeenRequest {
                url: request.url.to_string(),
                pinned_certificate_pem: request.pinned_certificate_pem.map(str::to_string),
                skip_verification: request.skip_verification,
                connect_address: request.connect_address.map(str::to_string),
            });
            Ok(valid_body())
        }
    }

    #[test]
    fn config_fetch_reads_url_pin_and_policy_from_the_endpoint() {
        let transport = RecordingTransport(std::cell::RefCell::new(None));
        let body = fetch_for_config(FETCH_CONFIG, &transport).unwrap();
        assert_eq!(body, String::from_utf8(valid_body()).unwrap());
        let seen = transport.0.borrow();
        let seen = seen.as_ref().unwrap();
        assert_eq!(seen.url, "https://u:p@vpn.example.com/subscription");
        assert_eq!(
            seen.pinned_certificate_pem.as_deref(),
            Some("-----BEGIN CERTIFICATE-----\nPIN\n-----END CERTIFICATE-----\n")
        );
        assert!(seen.skip_verification);
        assert_eq!(seen.connect_address.as_deref(), Some("1.1.1.1:443"));
    }

    #[test]
    fn config_fetch_drops_the_pin_for_a_foreign_subscription_host() {
        let config = FETCH_CONFIG.replace(
            "https://u:p@vpn.example.com/subscription",
            "https://other.example.net/subscription",
        );
        let transport = RecordingTransport(std::cell::RefCell::new(None));
        fetch_for_config(&config, &transport).unwrap();
        let seen = transport.0.borrow();
        let seen = seen.as_ref().unwrap();
        assert_eq!(seen.pinned_certificate_pem, None);
        assert_eq!(seen.connect_address, None);
        // The endpoint's verification policy must not leak to a foreign host.
        assert!(!seen.skip_verification);
    }

    fn endpoint() -> trusttunnel_settings::Endpoint {
        trusttunnel_settings::Endpoint {
            hostname: "vpn.example.com".to_string(),
            addresses: vec!["1.1.1.1:443".to_string()],
            username: "alice".to_string(),
            password: "old".to_string(),
            certificate: Some(
                "-----BEGIN CERTIFICATE-----\nPIN\n-----END CERTIFICATE-----\n".to_string(),
            ),
            ..trusttunnel_settings::Endpoint::default()
        }
    }

    #[test]
    fn request_reuses_endpoint_tls_params_when_host_matches_and_cert_pinned() {
        let endpoint = endpoint();
        let request = HttpRequest::for_endpoint("https://vpn.example.com/s", &endpoint);
        assert_eq!(
            request.pinned_certificate_pem,
            Some("-----BEGIN CERTIFICATE-----\nPIN\n-----END CERTIFICATE-----\n")
        );
        assert_eq!(request.connect_address, Some("1.1.1.1:443"));
        assert!(!request.skip_verification);
    }

    #[test]
    fn request_reuse_honors_skip_verification() {
        let mut endpoint = endpoint();
        endpoint.skip_verification = true;
        let request = HttpRequest::for_endpoint("https://vpn.example.com/s", &endpoint);
        assert_eq!(request.connect_address, Some("1.1.1.1:443"));
        assert!(request.skip_verification);
    }

    #[test]
    fn request_reuses_endpoint_params_for_skip_verification_without_cert() {
        let mut endpoint = endpoint();
        endpoint.certificate = None;
        endpoint.skip_verification = true;
        let request = HttpRequest::for_endpoint("https://vpn.example.com/s", &endpoint);
        assert_eq!(request.connect_address, Some("1.1.1.1:443"));
        assert!(request.skip_verification);
        assert_eq!(request.pinned_certificate_pem, None);
    }

    #[test]
    fn request_drops_endpoint_tls_params_when_host_differs() {
        let mut endpoint = endpoint();
        endpoint.skip_verification = true;
        let request = HttpRequest::for_endpoint("https://other.example.net/s", &endpoint);
        assert_eq!(request.pinned_certificate_pem, None);
        assert_eq!(request.connect_address, None);
        assert!(!request.skip_verification);
    }

    #[test]
    fn request_matches_host_case_insensitively() {
        let endpoint = endpoint();
        let request = HttpRequest::for_endpoint("https://VPN.example.COM/s", &endpoint);
        assert_eq!(request.connect_address, Some("1.1.1.1:443"));
    }

    #[test]
    fn request_makes_general_request_for_a_bare_subscription() {
        let endpoint = trusttunnel_settings::Endpoint::default();
        let request = HttpRequest::for_endpoint("https://vpn.example.com/s", &endpoint);
        assert_eq!(request.pinned_certificate_pem, None);
        assert_eq!(request.connect_address, None);
        assert!(!request.skip_verification);
    }

    #[test]
    fn request_treats_empty_certificate_as_absent() {
        let mut endpoint = endpoint();
        endpoint.certificate = Some(String::new());
        let request = HttpRequest::for_endpoint("https://vpn.example.com/s", &endpoint);
        assert_eq!(request.pinned_certificate_pem, None);
        assert_eq!(request.connect_address, None);
    }

    #[test]
    fn request_without_cert_and_without_skip_does_not_pin_the_address() {
        let mut endpoint = endpoint();
        endpoint.certificate = None;
        let request = HttpRequest::for_endpoint("https://vpn.example.com/s", &endpoint);
        assert_eq!(request.pinned_certificate_pem, None);
        assert_eq!(request.connect_address, None);
    }

    #[test]
    fn resolver_answers_the_subscription_netloc_without_dns() {
        // The unresolvable hostname proves no DNS lookup is attempted.
        let resolver =
            PinnedAddressResolver::new("https://unresolvable.invalid/s", "127.0.0.1:8443").unwrap();
        let addresses = ureq::Resolver::resolve(&resolver, "unresolvable.invalid:443").unwrap();
        assert_eq!(addresses, vec!["127.0.0.1:8443".parse().unwrap()]);
    }

    #[test]
    fn resolver_honors_the_url_port() {
        let resolver =
            PinnedAddressResolver::new("https://unresolvable.invalid:444/s", "127.0.0.1:8443")
                .unwrap();
        let addresses = ureq::Resolver::resolve(&resolver, "unresolvable.invalid:444").unwrap();
        assert_eq!(addresses, vec!["127.0.0.1:8443".parse().unwrap()]);
        // A different port on the same host falls back to DNS.
        assert!(ureq::Resolver::resolve(&resolver, "unresolvable.invalid:443").is_err());
    }

    #[test]
    fn resolver_falls_back_to_dns_for_other_netlocs() {
        let resolver =
            PinnedAddressResolver::new("https://unresolvable.invalid/s", "127.0.0.1:8443").unwrap();
        let addresses = ureq::Resolver::resolve(&resolver, "localhost:443").unwrap();
        assert!(!addresses.is_empty());
    }

    #[test]
    fn resolver_rejects_an_unusable_connect_address() {
        assert!(PinnedAddressResolver::new("https://h/s", "not-an-address").is_err());
    }

    #[test]
    fn config_fetch_without_subscription_is_a_distinct_error() {
        let config = FETCH_CONFIG.replace("[endpoint.subscription]", "[endpoint.other]");
        let err = fetch_for_config(&config, &FakeTransport(Ok(valid_body()))).unwrap_err();
        assert_eq!(err.to_string(), "No subscription URL configured.");
    }

    #[test]
    fn config_fetch_with_empty_url_is_a_distinct_error() {
        let config = FETCH_CONFIG.replace("https://u:p@vpn.example.com/subscription", "");
        let err = fetch_for_config(&config, &FakeTransport(Ok(valid_body()))).unwrap_err();
        assert_eq!(err.to_string(), "No subscription URL configured.");
    }

    #[test]
    fn config_fetch_with_invalid_config_is_a_parse_error() {
        let err =
            fetch_for_config("not [valid toml", &FakeTransport(Ok(valid_body()))).unwrap_err();
        assert!(
            err.to_string().contains("Failed to parse config"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn config_fetch_parse_error_does_not_leak_credentials() {
        // The unterminated string puts the parse error on the URL line.
        let config = "[endpoint.subscription]\nurl = \"https://u:p@vpn.example.com/subscription\n";
        let err = fetch_for_config(config, &FakeTransport(Ok(valid_body()))).unwrap_err();
        assert!(
            err.to_string().contains("Failed to parse config"),
            "unexpected: {err}"
        );
        assert!(!err.to_string().contains("u:p@"), "unexpected: {err}");
    }
}
