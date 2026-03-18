use std::sync::Arc;
use russh::client;
use russh::ChannelMsg;
use serde::Deserialize;
use tauri::Emitter;

// ─── Portable data directory (next to exe) ─────────

pub fn portable_data_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

// ─── Event Payloads ────────────────────────────────

#[derive(Clone, serde::Serialize)]
pub struct DeployStepPayload {
    pub step: String,
    pub status: String,
    pub message: String,
}

#[derive(Clone, serde::Serialize)]
pub struct DeployLogPayload {
    pub message: String,
    pub level: String,
}

// ─── Endpoint Settings (from GUI wizard) ───────────

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSettings {
    pub listen_address: String,
    pub vpn_username: String,
    pub vpn_password: String,
    pub cert_type: String,
    pub domain: String,
    #[allow(dead_code)]
    pub client_name: String,
    #[serde(default)]
    pub email: String,
}

// ─── SSH Handler ───────────────────────────────────

struct SshHandler;

#[async_trait::async_trait]
impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

// ─── Helpers ───────────────────────────────────────

fn emit_step(app: &tauri::AppHandle, step: &str, status: &str, message: &str) {
    eprintln!("[deploy] step={step} status={status} msg={message}");
    app.emit(
        "deploy-step",
        DeployStepPayload {
            step: step.into(),
            status: status.into(),
            message: message.into(),
        },
    )
    .ok();
}

fn emit_log(app: &tauri::AppHandle, level: &str, message: &str) {
    if message.trim().is_empty() {
        return;
    }
    eprintln!("[deploy-log] [{level}] {message}");
    app.emit(
        "deploy-log",
        DeployLogPayload {
            message: message.into(),
            level: level.into(),
        },
    )
    .ok();
}

/// Execute a command on the remote server, streaming output to the frontend.
async fn exec_command(
    handle: &client::Handle<SshHandler>,
    app: &tauri::AppHandle,
    command: &str,
) -> Result<(String, i32), String> {
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Ошибка открытия SSH-канала: {e}"))?;

    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|e| format!("Ошибка выполнения команды: {e}"))?;

    let mut stdout = String::new();
    let mut exit_code: i32 = -1;

    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => {
                let text = String::from_utf8_lossy(data);
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        emit_log(app, "info", trimmed);
                    }
                }
                stdout.push_str(&text);
            }
            ChannelMsg::ExtendedData { ref data, .. } => {
                let text = String::from_utf8_lossy(data);
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        emit_log(app, "warn", trimmed);
                    }
                }
                stdout.push_str(&text);
            }
            ChannelMsg::ExitStatus { exit_status } => {
                exit_code = exit_status as i32;
            }
            _ => {}
        }
    }

    Ok((stdout, exit_code))
}

/// Build the shell command that directly creates all TrustTunnel config files.
/// This bypasses setup_wizard entirely (no TTY required).
fn build_configure_commands(settings: &EndpointSettings, sudo: &str) -> String {
    let dir = "/opt/trusttunnel";
    let hostname = if !settings.domain.is_empty() {
        settings.domain.clone()
    } else {
        "trusttunnel.local".to_string()
    };

    // 1. credentials.toml
    let credentials = format!(
        r#"[[client]]
username = "{}"
password = "{}""#,
        settings.vpn_username, settings.vpn_password
    );

    // 2. rules.toml (empty = allow all)
    let rules = r#"# No filtering rules — all connections allowed"#;

    // 3. vpn.toml (main settings)
    let vpn = format!(
        r#"listen_address = "{}"
ipv6_available = false
allow_private_network_connections = false
tls_handshake_timeout_secs = 10
client_listener_timeout_secs = 600
connection_establishment_timeout_secs = 30
tcp_connections_timeout_secs = 604800
udp_connections_timeout_secs = 300
credentials_file = "credentials.toml"
rules_file = "rules.toml"

[listen_protocols]

[listen_protocols.http1]
upload_buffer_size = 32768

[listen_protocols.http2]
initial_connection_window_size = 8388608
initial_stream_window_size = 131072
max_concurrent_streams = 1000
max_frame_size = 16384
header_table_size = 65536

[listen_protocols.quic]
recv_udp_payload_size = 1350
send_udp_payload_size = 1350
initial_max_data = 104857600
initial_max_stream_data_bidi_local = 1048576
initial_max_stream_data_bidi_remote = 1048576
initial_max_stream_data_uni = 1048576
initial_max_streams_bidi = 4096
initial_max_streams_uni = 4096
max_connection_window = 25165824
max_stream_window = 16777216
disable_active_migration = true
enable_early_data = true
message_queue_capacity = 4096

[forward_protocol]
direct = {{}}"#,
        settings.listen_address
    );

    // 4. hosts.toml (TLS certs — main hosts only, ping_hosts requires unique hostname)
    let hosts = format!(
        r#"[[main_hosts]]
hostname = "{hostname}"
cert_chain_path = "certs/cert.pem"
private_key_path = "certs/key.pem""#
    );

    // Build the full shell script
    let email_flag = if !settings.email.is_empty() {
        format!("-m {}", settings.email)
    } else {
        "--register-unsafely-without-email".to_string()
    };
    let cert_cmd = match settings.cert_type.as_str() {
        "letsencrypt" => {
            // For Let's Encrypt: install certbot and get cert
            format!(
                r#"
# Install certbot and get Let's Encrypt certificate
if command -v apt-get >/dev/null 2>&1; then
    {sudo}apt-get install -y -qq certbot 2>/dev/null
elif command -v dnf >/dev/null 2>&1; then
    {sudo}dnf install -y -q certbot 2>/dev/null
elif command -v yum >/dev/null 2>&1; then
    {sudo}yum install -y -q certbot 2>/dev/null
fi
{sudo}certbot certonly --standalone -d {hostname} --non-interactive --agree-tos {email_flag} --http-01-port 80
{sudo}mkdir -p {dir}/certs
{sudo}cp /etc/letsencrypt/live/{hostname}/fullchain.pem {dir}/certs/cert.pem
{sudo}cp /etc/letsencrypt/live/{hostname}/privkey.pem {dir}/certs/key.pem

# Setup auto-renewal cron (renew + copy certs + restart service)
{sudo}bash -c 'cat > /etc/cron.d/trusttunnel-cert-renew << CRON_EOF
0 3 * * * root certbot renew --quiet --deploy-hook "cp /etc/letsencrypt/live/{hostname}/fullchain.pem {dir}/certs/cert.pem && cp /etc/letsencrypt/live/{hostname}/privkey.pem {dir}/certs/key.pem && systemctl restart trusttunnel"
CRON_EOF'
"#
            )
        }
        _ => {
            // Self-signed certificate via openssl
            format!(
                r#"
# Generate self-signed certificate
{sudo}mkdir -p {dir}/certs
{sudo}openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout {dir}/certs/key.pem -out {dir}/certs/cert.pem \
    -days 3650 -nodes -subj '/CN={hostname}'
"#
            )
        }
    };

    format!(
        r#"set -e

# Write config files
{sudo}tee {dir}/credentials.toml > /dev/null << 'CREDS_EOF'
{credentials}
CREDS_EOF

{sudo}tee {dir}/rules.toml > /dev/null << 'RULES_EOF'
{rules}
RULES_EOF

{sudo}tee {dir}/vpn.toml > /dev/null << 'VPN_EOF'
{vpn}
VPN_EOF

{sudo}tee {dir}/hosts.toml > /dev/null << 'HOSTS_EOF'
{hosts}
HOSTS_EOF
{cert_cmd}
echo "Configuration files created successfully"
"#
    )
}

// ─── Main Deploy Function ──────────────────────────

pub async fn deploy_server(
    app: &tauri::AppHandle,
    host: String,
    port: u16,
    ssh_user: String,
    ssh_password: String,
    settings: EndpointSettings,
) -> Result<String, String> {
    // ── Step 1: SSH Connect ──
    emit_step(app, "connect", "progress", "Подключение к серверу...");

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(120)),
        ..Default::default()
    });

    let mut handle = client::connect(config, (host.as_str(), port), SshHandler)
        .await
        .map_err(|e| {
            let msg = format!("Не удалось подключиться к {host}:{port} — {e}");
            emit_step(app, "connect", "error", &msg);
            msg
        })?;

    emit_step(app, "connect", "ok", "Подключено к серверу");

    // ── Step 2: Authenticate ──
    emit_step(app, "auth", "progress", "Авторизация...");

    let auth_ok = handle
        .authenticate_password(&ssh_user, &ssh_password)
        .await
        .map_err(|e| {
            let msg = format!("Ошибка авторизации: {e}");
            emit_step(app, "auth", "error", &msg);
            msg
        })?;

    if !auth_ok {
        let msg = "Неверный SSH логин или пароль";
        emit_step(app, "auth", "error", msg);
        return Err(msg.into());
    }

    emit_step(app, "auth", "ok", "Авторизация успешна");

    // ── Step 3: Check environment ──
    emit_step(app, "check", "progress", "Проверка сервера...");

    let (os_info, _) = exec_command(
        &handle,
        app,
        "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo 'Unknown OS'",
    )
    .await?;

    let (arch_info, _) = exec_command(&handle, app, "uname -m").await?;

    // Check if running as root
    let (whoami, _) = exec_command(&handle, app, "whoami").await?;
    let is_root = whoami.trim() == "root";

    emit_log(
        app,
        "info",
        &format!(
            "Сервер: {} ({}) / пользователь: {}",
            os_info.trim(),
            arch_info.trim(),
            whoami.trim()
        ),
    );

    if !is_root {
        // Check if sudo is available without password
        let (_, sudo_code) = exec_command(&handle, app, "sudo -n true 2>/dev/null").await?;
        if sudo_code != 0 {
            let msg = "Нужны права root. Подключитесь как root или настройте sudo без пароля.";
            emit_step(app, "check", "error", msg);
            return Err(msg.into());
        }
    }

    let sudo = if is_root { "" } else { "sudo " };

    emit_step(app, "check", "ok", "Сервер готов");

    // ── Step 3.5: Update system packages ──
    emit_step(app, "update", "progress", "Обновление системных пакетов...");

    let update_cmd = format!(
        "if command -v apt-get >/dev/null 2>&1; then \
             export DEBIAN_FRONTEND=noninteractive && \
             {sudo}apt-get update -qq && \
             {sudo}apt-get upgrade -y -qq && \
             {sudo}apt-get install -y -qq curl iptables; \
         elif command -v dnf >/dev/null 2>&1; then \
             {sudo}dnf upgrade -y -q && \
             {sudo}dnf install -y -q curl iptables; \
         elif command -v yum >/dev/null 2>&1; then \
             {sudo}yum update -y -q && \
             {sudo}yum install -y -q curl iptables; \
         fi"
    );

    let (_, update_code) = exec_command(&handle, app, &update_cmd).await?;

    if update_code != 0 {
        emit_log(app, "warn", "Не удалось обновить пакеты. Продолжаем установку...");
    }

    emit_step(app, "update", "ok", "Система обновлена");

    // ── Step 4: Install TrustTunnel Endpoint ──
    emit_step(app, "install", "progress", "Установка TrustTunnel Endpoint...");

    // Stop existing service if running (ignore errors)
    let stop_cmd = format!("{sudo}systemctl stop trusttunnel 2>/dev/null; sleep 1; true");
    exec_command(&handle, app, &stop_cmd).await.ok();

    // Use -a y flag to auto-answer interactive prompts (built into the install script)
    let install_cmd = format!(
        "curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh -o /tmp/tt_install.sh && {sudo}sh /tmp/tt_install.sh -a y -v && rm -f /tmp/tt_install.sh"
    );

    let (_, install_code) = exec_command(&handle, app, &install_cmd).await?;

    if install_code != 0 {
        let msg = format!("Установка завершилась с ошибкой (код {install_code})");
        emit_step(app, "install", "error", &msg);
        return Err(msg);
    }

    // Verify installation
    let (_, verify_code) = exec_command(
        &handle,
        app,
        "test -f /opt/trusttunnel/setup_wizard && test -f /opt/trusttunnel/trusttunnel_endpoint",
    )
    .await?;

    if verify_code != 0 {
        let msg = "Файлы TrustTunnel не найдены в /opt/trusttunnel/ после установки";
        emit_step(app, "install", "error", msg);
        return Err(msg.into());
    }

    emit_step(app, "install", "ok", "TrustTunnel Endpoint установлен");

    // ── Step 5: Create config files directly (no TTY needed) ──
    emit_step(app, "configure", "progress", "Создание конфигурации Endpoint...");

    // Validate domain for Let's Encrypt before attempting
    if settings.cert_type == "letsencrypt" {
        let domain = if !settings.domain.is_empty() {
            settings.domain.clone()
        } else {
            "trusttunnel.local".to_string()
        };
        let invalid = domain.ends_with(".local")
            || domain.ends_with(".localhost")
            || domain.ends_with(".test")
            || domain.ends_with(".example")
            || domain.ends_with(".invalid")
            || !domain.contains('.');
        if invalid {
            let msg = format!(
                "Let's Encrypt не может выдать сертификат для '{}'. Укажите публичный домен или выберите самоподписанный сертификат.",
                domain
            );
            emit_step(app, "configure", "error", &msg);
            return Err(msg);
        }
    }

    let configure_cmd = build_configure_commands(&settings, sudo);

    let (_, cfg_code) = exec_command(&handle, app, &configure_cmd).await?;

    if cfg_code != 0 {
        let msg = "Не удалось создать файлы конфигурации. Проверьте логи.";
        emit_step(app, "configure", "error", msg);
        return Err(msg.into());
    }

    // Verify certs were created
    let (cert_check, cert_code) = exec_command(
        &handle, app,
        "test -f /opt/trusttunnel/certs/cert.pem && test -f /opt/trusttunnel/certs/key.pem && echo OK"
    ).await?;

    if cert_code != 0 || !cert_check.contains("OK") {
        let msg = "Сертификаты не были созданы. Проверьте логи (openssl/certbot).";
        emit_step(app, "configure", "error", msg);
        return Err(msg.into());
    }
    emit_log(app, "info", "Сертификаты созданы ✓");

    // Pre-flight: run endpoint briefly to verify config is valid
    let (preflight, _preflight_code) = exec_command(
        &handle, app,
        &format!("cd /opt/trusttunnel && timeout 2 {sudo}./trusttunnel_endpoint vpn.toml hosts.toml 2>&1 || true")
    ).await?;
    emit_log(app, "debug", &format!("Pre-flight output: {preflight}"));

    // Check for fatal config errors (but ignore timeout exit which is expected)
    if preflight.to_lowercase().contains("error") && preflight.to_lowercase().contains("pars") {
        let msg = format!("Ошибка в конфигурации endpoint: {}", preflight.trim());
        emit_step(app, "configure", "error", &msg);
        return Err(msg);
    }

    emit_step(app, "configure", "ok", "Конфигурация Endpoint создана и проверена");

    // ── Step 6: Start systemd service ──
    emit_step(app, "service", "progress", "Запуск сервиса...");

    // Stop existing service first, then copy template and restart
    let service_cmds = format!(
        "{sudo}systemctl stop trusttunnel 2>/dev/null; \
         cd /opt/trusttunnel && \
         {sudo}cp -f trusttunnel.service.template /etc/systemd/system/trusttunnel.service 2>/dev/null; \
         {sudo}systemctl daemon-reload && \
         {sudo}systemctl enable --now trusttunnel"
    );

    let (_, svc_code) = exec_command(&handle, app, &service_cmds).await?;

    if svc_code != 0 {
        emit_log(app, "warn", "Не удалось запустить systemd сервис. Возможно, нужна ручная настройка.");
    }

    // Wait for service to start and verify it's running
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Check service status
    let (svc_status, _) = exec_command(
        &handle, app,
        &format!("{sudo}systemctl is-active trusttunnel 2>&1")
    ).await?;
    let is_active = svc_status.trim() == "active";

    if !is_active {
        // Get journal logs to diagnose the issue
        let (journal, _) = exec_command(
            &handle, app,
            &format!("{sudo}journalctl -u trusttunnel --no-pager -n 30 2>&1")
        ).await?;
        emit_log(app, "error", &format!("Сервис не запустился. Статус: {}", svc_status.trim()));
        for line in journal.lines().take(30) {
            emit_log(app, "warn", line);
        }

        // Also check the service file contents for debugging
        let (svc_file, _) = exec_command(
            &handle, app,
            "cat /etc/systemd/system/trusttunnel.service 2>&1"
        ).await?;
        emit_log(app, "debug", &format!("Service file:\n{svc_file}"));

        // Check what config files exist
        let (ls_output, _) = exec_command(
            &handle, app,
            "ls -la /opt/trusttunnel/*.toml /opt/trusttunnel/certs/ 2>&1"
        ).await?;
        emit_log(app, "debug", &format!("Config files:\n{ls_output}"));

        let msg = "TrustTunnel Endpoint не запустился. Смотрите логи для диагностики.";
        emit_step(app, "service", "error", msg);
        return Err(msg.into());
    }

    // Check if the port is actually listening
    let listen_port = settings.listen_address.split(':').last().unwrap_or("443");
    let (port_check, _) = exec_command(
        &handle, app,
        &format!("ss -tlnp | grep :{listen_port} || echo 'PORT_NOT_LISTENING'")
    ).await?;

    if port_check.contains("PORT_NOT_LISTENING") {
        emit_log(app, "warn", &format!("Порт {listen_port} ещё не слушает. Возможно, сервису нужно больше времени."));
    } else {
        emit_log(app, "info", &format!("Порт {listen_port} слушает ✓"));
    }

    emit_step(app, "service", "ok", "Сервис запущен и работает");

    // ── Step 7: Generate client config via trusttunnel_endpoint export ──
    emit_step(app, "export", "progress", "Генерация клиентского конфига...");

    // Use the endpoint's own export to get proper config with certificate PEM
    let export_address = if !settings.domain.is_empty() {
        format!("{}:{}", settings.domain, settings.listen_address.split(':').last().unwrap_or("443"))
    } else {
        let port = settings.listen_address.split(':').last().unwrap_or("443");
        format!("{host}:{port}")
    };

    let export_cmd = format!(
        "cd /opt/trusttunnel && {sudo}./trusttunnel_endpoint vpn.toml hosts.toml -c {user} -a {addr} --format toml 2>&1",
        sudo = sudo,
        user = settings.vpn_username,
        addr = export_address,
    );

    let (export_output, export_code) = exec_command(&handle, app, &export_cmd).await?;

    if export_code != 0 || export_output.trim().is_empty() {
        emit_log(app, "error", &format!("Export failed (code {export_code}): {export_output}"));
        let msg = format!(
            "Не удалось экспортировать конфиг (код {}). Пользователь '{}' не найден или ошибка endpoint.",
            export_code, settings.vpn_username
        );
        emit_step(app, "export", "error", &msg);
        return Err(msg);
    }

    // Extract only the TOML part (skip warning lines starting with timestamp or empty lines before TOML)
    let endpoint_section: String = export_output
        .lines()
        .skip_while(|l| !l.starts_with('#') && !l.starts_with("hostname"))
        .collect::<Vec<_>>()
        .join("\n");

    // Wrap with client-side settings
    let client_toml = format!(
        r#"# TrustTunnel Client Configuration
# Generated by TrustTunnel Setup Wizard

loglevel = "info"
vpn_mode = "general"
killswitch_enabled = true
post_quantum_group_enabled = false

[endpoint]
{endpoint_section}

[listener.tun]
mtu_size = 1280
change_system_dns = true
included_routes = ["0.0.0.0/0"]
excluded_routes = []
"#
    );

    // Enable anti_dpi by default
    let client_toml = client_toml.replace("anti_dpi = false", "anti_dpi = true");

    emit_log(app, "debug", &format!("Generated client config:\n{client_toml}"));
    emit_step(app, "export", "ok", "Конфиг сгенерирован");

    // ── Step 8: Save config locally (portable — next to exe) ──
    emit_step(app, "save", "progress", "Сохранение конфигурации...");

    let config_dir = portable_data_dir();

    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Не удалось создать директорию: {e}"))?;

    let client_config_path = config_dir.join("trusttunnel_client.toml");
    std::fs::write(&client_config_path, &client_toml)
        .map_err(|e| format!("Не удалось записать клиентский конфиг: {e}"))?;

    let config_path_str = client_config_path.to_string_lossy().to_string();
    emit_log(app, "info", &format!("Конфиг сохранён: {config_path_str}"));
    emit_step(app, "save", "ok", "Конфигурация сохранена");

    // ── Disconnect ──
    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    emit_step(app, "done", "ok", "Всё готово! Сервер настроен и запущен.");

    Ok(config_path_str)
}

// ─── Diagnose Server ──────────────────────────────

pub async fn diagnose_server(
    app: &tauri::AppHandle,
    host: String,
    port: u16,
    ssh_user: String,
    ssh_password: String,
) -> Result<String, String> {
    let config = russh::client::Config::default();
    let mut handle = russh::client::connect(
        Arc::new(config),
        (host.as_str(), port),
        SshHandler,
    )
    .await
    .map_err(|e| format!("SSH connect failed: {e}"))?;

    handle
        .authenticate_password(&ssh_user, &ssh_password)
        .await
        .map_err(|e| format!("SSH auth failed: {e}"))?;

    let mut report = String::new();

    // Service status
    let (status, _) = exec_command(&handle, app, "systemctl is-active trusttunnel 2>&1").await
        .unwrap_or(("unknown".into(), -1));
    report.push_str(&format!("Service status: {}\n", status.trim()));

    // Journal logs
    let (journal, _) = exec_command(&handle, app, "journalctl -u trusttunnel --no-pager -n 30 2>&1").await
        .unwrap_or(("no logs".into(), -1));
    report.push_str(&format!("\n=== Journal (last 30 lines) ===\n{journal}\n"));

    // Port check
    let (ports, _) = exec_command(&handle, app, "ss -tlnp 2>&1 | head -20").await
        .unwrap_or(("unknown".into(), -1));
    report.push_str(&format!("\n=== Listening ports ===\n{ports}\n"));

    // Config files
    let (ls, _) = exec_command(&handle, app, "ls -la /opt/trusttunnel/ 2>&1").await
        .unwrap_or(("unknown".into(), -1));
    report.push_str(&format!("\n=== /opt/trusttunnel/ ===\n{ls}\n"));

    // Service file
    let (svc, _) = exec_command(&handle, app, "cat /etc/systemd/system/trusttunnel.service 2>&1").await
        .unwrap_or(("unknown".into(), -1));
    report.push_str(&format!("\n=== Service file ===\n{svc}\n"));

    // vpn.toml
    let (vpn_cfg, _) = exec_command(&handle, app, "cat /opt/trusttunnel/vpn.toml 2>&1").await
        .unwrap_or(("not found".into(), -1));
    report.push_str(&format!("\n=== vpn.toml ===\n{vpn_cfg}\n"));

    // hosts.toml
    let (hosts_cfg, _) = exec_command(&handle, app, "cat /opt/trusttunnel/hosts.toml 2>&1").await
        .unwrap_or(("not found".into(), -1));
    report.push_str(&format!("\n=== hosts.toml ===\n{hosts_cfg}\n"));

    // Certs
    let (certs, _) = exec_command(&handle, app, "ls -la /opt/trusttunnel/certs/ 2>&1").await
        .unwrap_or(("not found".into(), -1));
    report.push_str(&format!("\n=== Certs ===\n{certs}\n"));

    handle.disconnect(russh::Disconnect::ByApplication, "", "en").await.ok();

    Ok(report)
}

// ─── Check & Uninstall ────────────────────────────

/// Check if TrustTunnel is already installed on the server.
/// Returns JSON: { installed: bool, version: String, service_active: bool }
pub async fn check_server_installation(
    app: &tauri::AppHandle,
    host: String,
    port: u16,
    ssh_user: String,
    ssh_password: String,
) -> Result<serde_json::Value, String> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    });

    let mut handle = client::connect(config, (host.as_str(), port), SshHandler)
        .await
        .map_err(|e| format!("SSH connect failed: {e}"))?;

    let auth_ok = handle
        .authenticate_password(&ssh_user, &ssh_password)
        .await
        .map_err(|e| format!("SSH auth failed: {e}"))?;

    if !auth_ok {
        return Err("Неверный SSH логин или пароль".into());
    }

    // Check for binary
    let (bin_check, _bin_code) = exec_command(
        &handle, app,
        "test -f /opt/trusttunnel/trusttunnel_endpoint && echo TT_EXISTS || echo TT_MISSING"
    ).await?;
    let installed = bin_check.trim().contains("TT_EXISTS");

    // Get version if installed
    let version = if installed {
        let (ver, _) = exec_command(
            &handle, app,
            "/opt/trusttunnel/trusttunnel_endpoint --version 2>/dev/null || echo unknown"
        ).await?;
        ver.trim().to_string()
    } else {
        String::new()
    };

    // Check service status
    let (svc_status, _) = exec_command(
        &handle, app,
        "systemctl is-active trusttunnel 2>/dev/null || echo inactive"
    ).await?;
    let service_active = svc_status.trim() == "active";

    handle.disconnect(russh::Disconnect::ByApplication, "", "en").await.ok();

    Ok(serde_json::json!({
        "installed": installed,
        "version": version,
        "serviceActive": service_active,
    }))
}

/// Completely remove TrustTunnel from the server.
pub async fn uninstall_server(
    app: &tauri::AppHandle,
    host: String,
    port: u16,
    ssh_user: String,
    ssh_password: String,
) -> Result<(), String> {
    emit_step(app, "uninstall", "progress", "Подключение к серверу...");

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(120)),
        ..Default::default()
    });

    let mut handle = client::connect(config, (host.as_str(), port), SshHandler)
        .await
        .map_err(|e| {
            let msg = format!("SSH connect failed: {e}");
            emit_step(app, "uninstall", "error", &msg);
            msg
        })?;

    let auth_ok = handle
        .authenticate_password(&ssh_user, &ssh_password)
        .await
        .map_err(|e| {
            let msg = format!("SSH auth failed: {e}");
            emit_step(app, "uninstall", "error", &msg);
            msg
        })?;

    if !auth_ok {
        let msg = "Неверный SSH логин или пароль";
        emit_step(app, "uninstall", "error", msg);
        return Err(msg.into());
    }

    // Determine sudo
    let (whoami, _) = exec_command(&handle, app, "whoami").await?;
    let sudo = if whoami.trim() == "root" { "" } else { "sudo " };

    emit_step(app, "uninstall", "progress", "Удаление TrustTunnel...");

    // Run full uninstall as a single script for reliability
    let uninstall_script = format!(
        r#"set -x
echo "=== BEFORE: listing /opt/trusttunnel ==="
ls -la /opt/trusttunnel/ 2>&1 || echo "(dir does not exist)"

echo "=== Step 1: Stop systemd service ==="
{sudo}systemctl stop trusttunnel 2>/dev/null || true
{sudo}systemctl disable trusttunnel 2>/dev/null || true

echo "=== Step 2: Kill processes ==="
{sudo}killall -9 trusttunnel_endpoint 2>/dev/null || true
{sudo}killall -9 setup_wizard 2>/dev/null || true
sleep 1

echo "=== Step 3: Remove systemd units ==="
{sudo}rm -f /etc/systemd/system/trusttunnel.service
{sudo}rm -f /etc/systemd/system/trusttunnel*.service
{sudo}systemctl daemon-reload

echo "=== Step 4: Remove /opt/trusttunnel ==="
{sudo}rm -rfv /opt/trusttunnel

echo "=== Step 5: Remove certbot cron ==="
{sudo}rm -f /etc/cron.d/trusttunnel-cert-renew 2>/dev/null || true

echo "=== Step 6: Remove binaries from PATH ==="
{sudo}rm -fv /usr/local/bin/trusttunnel* 2>/dev/null || true
{sudo}rm -fv /usr/bin/trusttunnel* 2>/dev/null || true

echo "=== Step 7: Search for any remaining trusttunnel files ==="
find / -maxdepth 4 -name '*trusttunnel*' -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null || true

echo "=== VERIFY ==="
if test -d /opt/trusttunnel; then
    echo "UNINSTALL_FAILED"
else
    echo "UNINSTALL_OK"
fi
"#
    );

    let (output, code) = exec_command(&handle, app, &uninstall_script).await?;

    if output.contains("UNINSTALL_FAILED") || code != 0 {
        let msg = format!("Не удалось полностью удалить TrustTunnel (код {}). Смотрите логи.", code);
        emit_step(app, "uninstall", "error", &msg);
        handle.disconnect(russh::Disconnect::ByApplication, "", "en").await.ok();
        return Err(msg);
    }

    emit_log(app, "info", "TrustTunnel полностью удалён с сервера");

    handle.disconnect(russh::Disconnect::ByApplication, "", "en").await.ok();

    emit_step(app, "uninstall", "ok", "TrustTunnel удалён");
    Ok(())
}

// ─── Fetch existing config from server ────────────

/// Connect to a server where TrustTunnel is already installed,
/// export the client config via trusttunnel_endpoint, and save it locally.
pub async fn fetch_server_config(
    app: &tauri::AppHandle,
    host: String,
    port: u16,
    ssh_user: String,
    ssh_password: String,
    client_name: String,
) -> Result<String, String> {
    emit_step(app, "connect", "progress", "Подключение к серверу...");

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(60)),
        ..Default::default()
    });

    let mut handle = client::connect(config, (host.as_str(), port), SshHandler)
        .await
        .map_err(|e| {
            let msg = format!("Не удалось подключиться к {host}:{port} — {e}");
            emit_step(app, "connect", "error", &msg);
            msg
        })?;

    emit_step(app, "connect", "ok", "Подключено к серверу");

    emit_step(app, "auth", "progress", "Авторизация...");

    let auth_ok = handle
        .authenticate_password(&ssh_user, &ssh_password)
        .await
        .map_err(|e| {
            let msg = format!("Ошибка авторизации: {e}");
            emit_step(app, "auth", "error", &msg);
            msg
        })?;

    if !auth_ok {
        let msg = "Неверный SSH логин или пароль";
        emit_step(app, "auth", "error", msg);
        return Err(msg.into());
    }

    emit_step(app, "auth", "ok", "Авторизация успешна");

    // Check TrustTunnel is installed
    emit_step(app, "check", "progress", "Проверка TrustTunnel на сервере...");

    let (bin_check, _) = exec_command(
        &handle, app,
        "test -f /opt/trusttunnel/trusttunnel_endpoint && echo TT_EXISTS || echo TT_MISSING"
    ).await?;

    if !bin_check.contains("TT_EXISTS") {
        let msg = "TrustTunnel не найден на сервере (/opt/trusttunnel/trusttunnel_endpoint)";
        emit_step(app, "check", "error", msg);
        return Err(msg.into());
    }

    // Check config files exist
    let (cfg_check, _) = exec_command(
        &handle, app,
        "test -f /opt/trusttunnel/vpn.toml && test -f /opt/trusttunnel/hosts.toml && echo CFG_OK || echo CFG_MISSING"
    ).await?;

    if !cfg_check.contains("CFG_OK") {
        let msg = "Конфигурационные файлы не найдены на сервере (vpn.toml / hosts.toml)";
        emit_step(app, "check", "error", msg);
        return Err(msg.into());
    }

    emit_step(app, "check", "ok", "TrustTunnel установлен, конфиг найден");

    // Determine the server's listen address for the export command
    let (listen_raw, _) = exec_command(
        &handle, app,
        r#"grep -oP 'listen_address\s*=\s*"\K[^"]+' /opt/trusttunnel/vpn.toml 2>/dev/null || echo '0.0.0.0:443'"#
    ).await?;
    let listen_addr = listen_raw.trim();
    let listen_port = listen_addr.split(':').last().unwrap_or("443");

    // Try to determine the address the endpoint uses (domain from hosts.toml or fallback to host IP)
    let (hostname_raw, _) = exec_command(
        &handle, app,
        r#"grep -oP 'hostname\s*=\s*"\K[^"]+' /opt/trusttunnel/hosts.toml 2>/dev/null | head -1"#
    ).await?;
    let endpoint_hostname = hostname_raw.trim();
    let export_address = if !endpoint_hostname.is_empty() && endpoint_hostname != "trusttunnel.local" {
        format!("{endpoint_hostname}:{listen_port}")
    } else {
        format!("{host}:{listen_port}")
    };

    // Use the client_name provided, or default
    let name = if client_name.trim().is_empty() { "client" } else { client_name.trim() };

    emit_step(app, "export", "progress", "Экспорт клиентского конфига...");

    let (whoami, _) = exec_command(&handle, app, "whoami").await?;
    let sudo = if whoami.trim() == "root" { "" } else { "sudo " };

    // Pre-check: list available usernames from credentials.toml
    let (creds_raw, _) = exec_command(
        &handle, app,
        &format!("{sudo}grep -oP 'username\\s*=\\s*\"\\K[^\"]+' /opt/trusttunnel/credentials.toml 2>/dev/null || echo ''")
    ).await?;
    let available_users: Vec<&str> = creds_raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    if !available_users.is_empty() {
        emit_log(app, "info", &format!("Доступные пользователи: {}", available_users.join(", ")));
        if !available_users.iter().any(|u| *u == name) {
            let msg = format!(
                "Пользователь '{}' не найден в credentials.toml. Доступные: {}",
                name,
                available_users.join(", ")
            );
            emit_step(app, "export", "error", &msg);
            return Err(msg);
        }
    }

    let export_cmd = format!(
        "cd /opt/trusttunnel && {sudo}./trusttunnel_endpoint vpn.toml hosts.toml -c {name} -a {export_address} --format toml 2>&1"
    );

    let (export_output, export_code) = exec_command(&handle, app, &export_cmd).await?;

    if export_code != 0 || export_output.trim().is_empty() {
        emit_log(app, "error", &format!("Export failed (code {export_code}): {export_output}"));
        let msg = if !available_users.is_empty() {
            format!("Не удалось экспортировать конфиг (код {}). Доступные пользователи: {}", export_code, available_users.join(", "))
        } else {
            format!("Не удалось экспортировать конфиг (код {}). Проверьте credentials.toml на сервере.", export_code)
        };
        emit_step(app, "export", "error", &msg);
        return Err(msg);
    }

    // Extract only the TOML part
    let endpoint_section: String = export_output
        .lines()
        .skip_while(|l| !l.starts_with('#') && !l.starts_with("hostname"))
        .collect::<Vec<_>>()
        .join("\n");

    let client_toml = format!(
        r#"# TrustTunnel Client Configuration
# Fetched from server {host}

loglevel = "info"
vpn_mode = "general"
killswitch_enabled = true
post_quantum_group_enabled = false

[endpoint]
{endpoint_section}

[listener.tun]
mtu_size = 1280
change_system_dns = true
included_routes = ["0.0.0.0/0"]
excluded_routes = []
"#
    );

    // Enable anti_dpi by default
    let client_toml = client_toml.replace("anti_dpi = false", "anti_dpi = true");

    emit_step(app, "export", "ok", "Конфиг получен");

    // Save locally
    emit_step(app, "save", "progress", "Сохранение конфигурации...");

    let config_dir = portable_data_dir();
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Не удалось создать директорию: {e}"))?;

    let client_config_path = config_dir.join("trusttunnel_client.toml");
    std::fs::write(&client_config_path, &client_toml)
        .map_err(|e| format!("Не удалось записать клиентский конфиг: {e}"))?;

    let config_path_str = client_config_path.to_string_lossy().to_string();
    emit_log(app, "info", &format!("Конфиг сохранён: {config_path_str}"));
    emit_step(app, "save", "ok", "Конфигурация сохранена");

    handle.disconnect(russh::Disconnect::ByApplication, "", "en").await.ok();

    emit_step(app, "done", "ok", "Конфиг успешно получен с сервера!");

    Ok(config_path_str)
}

// ─── Utility functions ─────────────────────────────

/// Check if another trusttunnel_client process is running.
pub fn check_process_conflict() -> Option<String> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq trusttunnel_client*", "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("trusttunnel_client") {
            return Some("Обнаружен запущенный процесс TrustTunnel. Завершить его?".into());
        }
    }
    #[cfg(not(windows))]
    {
        let output = std::process::Command::new("pgrep")
            .args(["-f", "trusttunnel_client"])
            .output()
            .ok()?;
        if output.status.success() {
            return Some("Обнаружен запущенный процесс TrustTunnel. Завершить его?".into());
        }
    }
    None
}

/// Kill any running trusttunnel_client processes.
pub fn kill_existing_process() -> Result<(), String> {
    #[cfg(windows)]
    {
        std::process::Command::new("taskkill")
            .args(["/F", "/IM", "trusttunnel_client*"])
            .output()
            .map_err(|e| format!("Не удалось завершить процесс: {e}"))?;
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("pkill")
            .args(["-f", "trusttunnel_client"])
            .output()
            .map_err(|e| format!("Не удалось завершить процесс: {e}"))?;
    }
    Ok(())
}
