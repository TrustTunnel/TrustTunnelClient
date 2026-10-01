use crate::settings::{Listener, Settings, SocksListener, TunListener};
use crate::template_settings;
use crate::template_settings::ToTomlComment;
use std::fmt;
use std::fs;
use toml_edit::{value, Array, Document, Item, Table};

/// Failure to compose a settings document.
#[derive(Debug)]
pub enum ComposeError {
    Read { path: String, error: std::io::Error },
    Parse(toml_edit::TomlError),
    MissingTable(&'static str),
}

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComposeError::Read { path, error } => write!(f, "Couldn't read file '{path}': {error}"),
            ComposeError::Parse(error) => write!(f, "Couldn't parse the document: {error}"),
            ComposeError::MissingTable(name) => write!(f, "Missing [{name}] table in the document"),
        }
    }
}

impl std::error::Error for ComposeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ComposeError::Read { error, .. } => Some(error),
            ComposeError::Parse(error) => Some(error),
            ComposeError::MissingTable(_) => None,
        }
    }
}

pub fn compose_document(file: Option<&str>, settings: &Settings) -> Result<Document, ComposeError> {
    let doc = match file {
        Some(x) => read_existing_file(x)?,
        None => fabricate_template_document()?,
    };

    apply_to_document(doc, settings)
}

/// Apply `settings` onto an already-parsed document, preserving everything
/// the model does not represent.
pub fn apply_to_document(doc: Document, settings: &Settings) -> Result<Document, ComposeError> {
    let doc = fill_main_table(doc, settings);
    let doc = fill_endpoint_table(doc, settings)?;
    fill_listener_table(doc, settings)
}

fn read_existing_file(file: &str) -> Result<Document, ComposeError> {
    fs::read_to_string(file)
        .map_err(|error| ComposeError::Read {
            path: file.to_string(),
            error,
        })?
        .parse()
        .map_err(ComposeError::Parse)
}

fn fabricate_template_document() -> Result<Document, ComposeError> {
    format!(
        "{}\n{}\n{}",
        template_settings::MAIN_TABLE.as_str(),
        template_settings::ENDPOINT.as_str(),
        template_settings::COMMON_LISTENER_TABLE,
    )
    .parse()
    .map_err(ComposeError::Parse)
}

fn fill_main_table(mut doc: Document, settings: &Settings) -> Document {
    doc["loglevel"] = value(&settings.loglevel);
    doc["vpn_mode"] = value(&settings.vpn_mode);
    doc["killswitch_enabled"] = value(settings.killswitch_enabled);
    doc["post_quantum_group_enabled"] = value(settings.post_quantum_group_enabled);
    doc["exclusions"] = value(Array::from_iter(settings.exclusions.iter()));

    doc
}

fn fill_endpoint_table(mut doc: Document, settings: &Settings) -> Result<Document, ComposeError> {
    let endpoint = doc
        .get_mut("endpoint")
        .and_then(Item::as_table_mut)
        .ok_or(ComposeError::MissingTable("endpoint"))?;

    endpoint["hostname"] = value(&settings.endpoint.hostname);
    endpoint["addresses"] = value(Array::from_iter(settings.endpoint.addresses.iter()));
    endpoint["has_ipv6"] = value(settings.endpoint.has_ipv6);
    endpoint["username"] = value(&settings.endpoint.username);
    endpoint["password"] = value(&settings.endpoint.password);
    endpoint["client_random"] = value(&settings.endpoint.client_random);
    endpoint["skip_verification"] = value(settings.endpoint.skip_verification);
    endpoint["anti_dpi"] = value(settings.endpoint.anti_dpi);
    endpoint["certificate"] = value(settings.endpoint.certificate.as_deref().unwrap_or_default());
    endpoint["upstream_protocol"] = value(&settings.endpoint.upstream_protocol);
    endpoint["tls_profile"] = value(&settings.endpoint.tls_profile);
    endpoint["custom_sni"] = value(&settings.endpoint.custom_sni);
    endpoint["dns_upstreams"] = value(Array::from_iter(settings.endpoint.dns_upstreams.iter()));
    endpoint["name"] = value(settings.endpoint.name.as_deref().unwrap_or_default());
    if let Some(subscription) = &settings.endpoint.subscription {
        let mut table = Table::new();
        table["url"] = value(&subscription.url);
        if let Some(fetched_at) = &subscription.last_fetched_at {
            table["last_fetched_at"] = value(fetched_at);
        }
        endpoint["subscription"] = Item::Table(table);
    } else {
        endpoint.remove("subscription");
    }

    Ok(doc)
}

fn fill_listener_table(mut doc: Document, settings: &Settings) -> Result<Document, ComposeError> {
    let mut listener = doc
        .get_mut("listener")
        .and_then(Item::as_table_mut)
        .ok_or(ComposeError::MissingTable("listener"))?;

    let kind = settings.listener.to_kind_string();
    if !listener.contains_table(&kind) {
        doc.remove("listener");

        doc = format!(
            "{}\n{}\n{}\n{}",
            doc,
            template_settings::COMMON_LISTENER_TABLE,
            match &settings.listener {
                Listener::Socks(_) => template_settings::SOCKS_LISTENER.as_str(),
                Listener::Tun(_) => template_settings::TUN_LISTENER.as_str(),
            },
            match &settings.listener {
                Listener::Socks(_) => template_settings::TUN_LISTENER.to_toml_comment(),
                Listener::Tun(_) => template_settings::SOCKS_LISTENER.to_toml_comment(),
            },
        )
        .parse()
        .map_err(ComposeError::Parse)?;
        listener = doc
            .get_mut("listener")
            .and_then(Item::as_table_mut)
            .ok_or(ComposeError::MissingTable("listener"))?;
    }

    match &settings.listener {
        Listener::Socks(socks) => fill_socks_listener_table(listener, socks)?,
        Listener::Tun(tun) => fill_tun_listener_table(listener, tun)?,
    }

    Ok(doc)
}

fn fill_socks_listener_table(
    listener: &mut Table,
    settings: &SocksListener,
) -> Result<(), ComposeError> {
    let table = listener["socks"]
        .as_table_mut()
        .ok_or(ComposeError::MissingTable("listener.socks"))?;

    table["address"] = value(&settings.address);
    table["username"] = value(settings.username.as_deref().unwrap_or_default());
    table["password"] = value(settings.password.as_deref().unwrap_or_default());
    Ok(())
}

fn fill_tun_listener_table(
    listener: &mut Table,
    settings: &TunListener,
) -> Result<(), ComposeError> {
    let table = listener["tun"]
        .as_table_mut()
        .ok_or(ComposeError::MissingTable("listener.tun"))?;

    table["bound_if"] = value(&settings.bound_if);
    table["included_routes"] = value(Array::from_iter(settings.included_routes.iter()));
    table["excluded_routes"] = value(Array::from_iter(settings.excluded_routes.iter()));
    table["mtu_size"] = value(settings.mtu_size as i64);
    table["change_system_dns"] = value(settings.change_system_dns);
    table["device_name"] = value(&settings.device_name);
    table["use_existing"] = value(settings.use_existing);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{Listener, TunListener};
    use crate::{Endpoint, EndpointSubscription};

    fn test_settings(dns_upstreams: Vec<String>) -> Settings {
        Settings {
            loglevel: "info".into(),
            vpn_mode: "general".into(),
            killswitch_enabled: true,
            killswitch_allow_ports: vec![],
            post_quantum_group_enabled: true,
            exclusions_tcp_early_ack_enabled: false,
            exclusions_preresolve_enabled: true,
            exclusions_preresolve_max_queries: 0,
            exclusions_scannable_ports: Settings::default_exclusions_scannable_ports(),
            exclusions: vec![],
            endpoint: Endpoint {
                hostname: "vpn.example.com".into(),
                addresses: vec!["1.2.3.4:443".into()],
                has_ipv6: true,
                username: "alice".into(),
                password: "s3cr3t".into(),
                upstream_protocol: "http2".into(),
                dns_upstreams,
                ..Default::default()
            },
            listener: Listener::Tun(TunListener {
                bound_if: "".into(),
                included_routes: vec!["0.0.0.0/0".into()],
                excluded_routes: vec![],
                mtu_size: 1350,
                tcp_recv_buf_size: 0,
                tcp_send_buf_size: 0,
                change_system_dns: true,
                device_name: "".into(),
                use_existing: false,
            }),
        }
    }

    #[test]
    fn compose_writes_endpoint_dns_upstreams() {
        let settings = test_settings(vec!["tls://dns.adguard-dns.com".into()]);
        let doc = compose_document(None, &settings).unwrap();
        let output = doc.to_string();

        let parsed: toml::Value = output.parse().unwrap();
        let dns = parsed["endpoint"]["dns_upstreams"].as_array().unwrap();
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].as_str().unwrap(), "tls://dns.adguard-dns.com");
    }

    #[test]
    fn compose_writes_empty_dns_upstreams() {
        let settings = test_settings(vec![]);
        let doc = compose_document(None, &settings).unwrap();
        let output = doc.to_string();

        let parsed: toml::Value = output.parse().unwrap();
        let dns = parsed["endpoint"]["dns_upstreams"].as_array().unwrap();
        assert!(dns.is_empty());
    }

    #[test]
    fn compose_omits_root_legacy_dns_upstreams() {
        let settings = test_settings(vec!["tls://dns.adguard-dns.com".into()]);
        let doc = compose_document(None, &settings).unwrap();
        let output = doc.to_string();

        let parsed: toml::Value = output.parse().unwrap();
        assert!(parsed.get("dns_upstreams").is_none());
    }

    #[test]
    fn compose_writes_subscription_table() {
        let mut settings = Settings::default();
        settings.endpoint.subscription = Some(EndpointSubscription {
            url: "https://u:p@vpn.example.com/subscription".to_string(),
            last_fetched_at: Some("2026-07-28T12:00:00Z".to_string()),
        });
        let doc = compose_document(None, &settings).unwrap();
        let text = doc.to_string();
        assert!(text.contains("[endpoint.subscription]"));
        assert!(text.contains("url = \"https://u:p@vpn.example.com/subscription\""));
        assert!(text.contains("last_fetched_at = \"2026-07-28T12:00:00Z\""));
    }

    #[test]
    fn compose_omits_subscription_table_when_absent() {
        let settings = Settings::default();
        let doc = compose_document(None, &settings).unwrap();
        let endpoint = doc
            .get("endpoint")
            .and_then(Item::as_table)
            .expect("endpoint table missing");
        assert!(endpoint.get("subscription").is_none());
    }

    #[test]
    fn compose_writes_name_as_real_key() {
        let mut settings = Settings::default();
        settings.endpoint.name = Some("Example VPN".to_string());
        let doc = compose_document(None, &settings).unwrap();
        let text = doc.to_string();
        let endpoint_table = text
            .split("[endpoint]")
            .nth(1)
            .expect("endpoint table missing");
        assert!(endpoint_table.contains("name = \"Example VPN\""));

        let doc = compose_document(None, &Settings::default()).unwrap();
        assert_eq!(doc["endpoint"]["name"].as_str(), Some(""));
    }

    #[test]
    fn missing_endpoint_table_is_an_error() {
        let err = apply_to_document(Document::new(), &Settings::default()).unwrap_err();
        assert!(matches!(err, ComposeError::MissingTable("endpoint")));
    }

    #[test]
    fn missing_listener_table_is_an_error() {
        let doc: Document = "[endpoint]\n".parse().unwrap();
        let err = apply_to_document(doc, &Settings::default()).unwrap_err();
        assert!(matches!(err, ComposeError::MissingTable("listener")));
    }
}
