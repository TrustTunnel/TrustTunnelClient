use std::fs;
use toml_edit::{Array, Document, Item, Table, value};
use crate::settings::{Listener, Settings};
use crate::template_settings;
use crate::template_settings::ToTomlComment;

pub fn compose_document(file: Option<&str>, settings: &Settings) -> Document {
    let doc = match file {
        Some(x) => read_existing_file(x),
        None => fabricate_template_document(),
    };

    let doc = fill_main_table(doc, settings);
    let doc = fill_endpoint_table(doc, settings);
    fill_listener_table(doc, settings)
}

fn read_existing_file(file: &str) -> Document {
    fs::read_to_string(file)
        .unwrap_or_else(|_| panic!("Couldn't read file: {file}"))
        .parse()
        .expect("Couldn't parse file content")
}

fn fabricate_template_document() -> Document {
    format!(
        "{}\n{}\n{}",
        template_settings::MAIN_TABLE.as_str(),
        template_settings::ENDPOINT.as_str(),
        template_settings::COMMON_LISTENER_TABLE,
    )
        .parse()
        .expect("Couldn't parse fabricated document")
}

fn fill_main_table(mut doc: Document, settings: &Settings) -> Document {
    doc["loglevel"] = value(&settings.loglevel);
    doc["vpn_mode"] = value(&settings.vpn_mode);
    doc["killswitch_enabled"] = value(settings.killswitch_enabled);
    doc["exclusions"] = value(Array::from_iter(settings.exclusions.iter()));
    doc["dns_upstreams"] = value(Array::from_iter(settings.dns_upstreams.iter()));

    doc
}

fn fill_endpoint_table(mut doc: Document, settings: &Settings) -> Document {
    let endpoint = doc.get_mut("endpoint")
        .and_then(Item::as_table_mut)
        .expect("Endpoint table not found");

    endpoint["hostname"] = value(&settings.endpoint.hostname);
    endpoint["addresses"] = value(Array::from_iter(settings.endpoint.addresses.iter()));
    endpoint["username"] = value(&settings.endpoint.username);
    endpoint["password"] = value(&settings.endpoint.password);
    endpoint["skip_verification"] = value(settings.endpoint.skip_verification);
    endpoint["anti_dpi"] = value(settings.endpoint.anti_dpi);
    endpoint["certificate"] = value(
        settings.endpoint.certificate.as_deref().unwrap_or_default()
    );
    endpoint["upstream_protocol"] = value(&settings.endpoint.upstream_protocol);
    endpoint["upstream_fallback_protocol"] = value(
        settings.endpoint.upstream_fallback_protocol.as_deref().unwrap_or_default()
    );

    doc
}

fn fill_listener_table(mut doc: Document, settings: &Settings) -> Document {
    let mut listener = doc.get_mut("listener")
        .and_then(Item::as_table_mut)
        .expect("Listener table not found");

    let kind = settings.listener.to_kind_string();
    if !listener.contains_table(&kind) {
        doc.remove("listener");

        doc = format!(
            "{}\n{}\n{}\n{}",
            doc,
            template_settings::COMMON_LISTENER_TABLE,
            match kind.as_str() {
                "socks" => template_settings::SOCKS_LISTENER.as_str(),
                "tun" => template_settings::TUN_LISTENER.as_str(),
                _ => unreachable!(),
            },
            match kind.as_str() {
                "socks" => template_settings::TUN_LISTENER.to_toml_comment(),
                "tun" => template_settings::SOCKS_LISTENER.to_toml_comment(),
                _ => unreachable!(),
            },
        )
            .parse()
            .expect("Couldn't parse rebuilt document");
        listener = doc.get_mut("listener")
            .and_then(Item::as_table_mut)
            .unwrap();
    }

    match kind.as_str() {
        "socks" => fill_socks_listener_table(listener, settings),
        "tun" => fill_tun_listener_table(listener, settings),
        _ => unreachable!(),
    }

    doc
}

fn fill_socks_listener_table(table: &mut Table, settings: &Settings) {
    let table = table["socks"].as_table_mut()
        .expect("SOCKS listener table not found");
    let settings = match &settings.listener {
        Listener::Socks(x) => x,
        _ => unreachable!(),
    };

    table["address"] = value(&settings.address);
    table["username"] = value(settings.username.as_deref().unwrap_or_default());
    table["password"] = value(settings.password.as_deref().unwrap_or_default());
}

fn fill_tun_listener_table(table: &mut Table, settings: &Settings) {
    let table = table["tun"].as_table_mut()
        .expect("TUN listener table not found");
    let settings = match &settings.listener {
        Listener::Tun(x) => x,
        _ => unreachable!(),
    };

    table["bound_if"] = value(&settings.bound_if);
    table["included_routes"] = value(Array::from_iter(settings.included_routes.iter()));
    table["excluded_routes"] = value(Array::from_iter(settings.excluded_routes.iter()));
    table["mtu_size"] = value(settings.mtu_size as i64);
}
