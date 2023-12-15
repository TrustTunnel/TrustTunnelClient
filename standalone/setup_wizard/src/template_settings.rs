use std::iter::Iterator;
use once_cell::sync::Lazy;
use crate::settings::{Endpoint, Settings, SocksListener, TunListener};

#[cfg(target_family = "unix")]
const OS_LINE_ENDING: &str = "\n";
#[cfg(target_family = "windows")]
const OS_LINE_ENDING: &str = "\r\n";

pub trait ToTomlComment {
    fn to_toml_comment(&self) -> String;
}

impl ToTomlComment for &str {
    fn to_toml_comment(&self) -> String {
        self.lines()
            .map(|x| format!("# {x}"))
            .collect::<Vec<_>>()
            .join(OS_LINE_ENDING)
    }
}

impl ToTomlComment for String {
    fn to_toml_comment(&self) -> String {
        self.as_str().to_toml_comment()
    }
}

pub static MAIN_TABLE: Lazy<String> = Lazy::new(|| format!(
    r#"{}
loglevel = "{}"

{}
vpn_mode = "{}"

{}
killswitch_enabled = {}

{}
exclusions = []

{}
dns_upstreams = []
"#,
    Settings::doc_loglevel().to_toml_comment(),
    Settings::default_loglevel(),
    Settings::doc_vpn_mode().to_toml_comment(),
    Settings::default_vpn_mode(),
    Settings::doc_killswitch_enabled().to_toml_comment(),
    Settings::default_killswitch_enabled(),
    Settings::doc_exclusions().to_toml_comment(),
    Settings::doc_dns_upstreams().to_toml_comment(),
));

pub static ENDPOINT: Lazy<String> = Lazy::new(|| format!(
    r#"{}
[endpoint]
{}
hostname = ""
{}
addresses = []
{}
username = ""
{}
password = ""
{}
skip_verification = false
{}
certificate = ""
{}
upstream_protocol = "{}"
{}
upstream_fallback_protocol = ""
{}
anti_dpi = false
"#,
    Endpoint::doc().to_toml_comment(),
    Endpoint::doc_hostname().to_toml_comment(),
    Endpoint::doc_addresses().to_toml_comment(),
    Endpoint::doc_username().to_toml_comment(),
    Endpoint::doc_password().to_toml_comment(),
    Endpoint::doc_skip_verification().to_toml_comment(),
    Endpoint::doc_certificate().to_toml_comment(),
    Endpoint::doc_upstream_protocol().to_toml_comment(),
    Endpoint::default_upstream_protocol(),
    Endpoint::doc_upstream_fallback_protocol().to_toml_comment(),
    Endpoint::doc_anti_dpi().to_toml_comment(),
));

pub const COMMON_LISTENER_TABLE: &str = r#"
# Defines the way to listen to network traffic by the kind of the nested table.
# Possible types:
#   * socks: SOCKS5 proxy with UDP support,
#   * tun: TUN device.
[listener]
"#;

pub static SOCKS_LISTENER: Lazy<String> = Lazy::new(|| format!(
    r#"[listener.socks]
{}
address = "{}"
{}
username = ""
{}
password = ""
"#,
    SocksListener::doc_address().to_toml_comment(),
    SocksListener::default_address(),
    SocksListener::doc_username().to_toml_comment(),
    SocksListener::doc_password().to_toml_comment(),
));

pub static TUN_LISTENER: Lazy<String> = Lazy::new(|| format!(
    r#"[listener.tun]
{}
bound_if = "{}"
{}
included_routes = [{}]
{}
excluded_routes = [{}]
{}
mtu_size = {}
"#,
    TunListener::doc_bound_if().to_toml_comment(),
    TunListener::default_bound_if(),
    TunListener::doc_included_routes().to_toml_comment(),
    TunListener::default_included_routes()
        .iter()
        .map(|x| format!("\"{x}\","))
        .collect::<Vec<_>>()
        .join(OS_LINE_ENDING),
    TunListener::doc_excluded_routes().to_toml_comment(),
    TunListener::default_excluded_routes()
        .iter()
        .map(|x| format!("\"{x}\","))
        .collect::<Vec<_>>()
        .join(OS_LINE_ENDING),
    TunListener::doc_mtu_size().to_toml_comment(),
    TunListener::default_mtu_size(),
));
