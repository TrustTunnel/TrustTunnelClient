mod sidecar;
mod ssh_deploy;

use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::Emitter;
use tauri::Manager;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::RunEvent;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Force-kill ALL trusttunnel_client.exe processes system-wide.
/// Called before connecting and on app exit to avoid stale WinTUN locks.
fn kill_all_sidecar_processes() {
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/IM", "trusttunnel_client.exe"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();
}

/// Kill the sidecar stored in AppState, if any.
fn kill_sidecar_from_state(state: &AppState) {
    if let Ok(mut guard) = state.sidecar_child.lock() {
        if let Some(child) = guard.take() {
            child.child.kill().ok();
        }
    }
}

#[derive(Clone, Serialize)]
struct VpnLogPayload {
    message: String,
    level: String,
}

#[derive(Clone, Serialize)]
struct VpnStatusPayload {
    status: String,
    error: Option<String>,
}

struct AppState {
    sidecar_child: Arc<Mutex<Option<sidecar::SidecarChild>>>,
    disconnecting: Arc<Mutex<bool>>,
    is_connected: Arc<Mutex<bool>>,
}

#[tauri::command]
async fn vpn_connect(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    config_path: String,
    log_level: String,
) -> Result<(), String> {
    eprintln!("[vpn_connect] Called with config_path={config_path}, log_level={log_level}");

    // Emit log so user sees something immediately
    app.emit("vpn-log", VpnLogPayload {
        message: format!("Connecting with config: {config_path}"),
        level: "info".into(),
    }).ok();

    // Check and drop guard before async call
    {
        let guard = state
            .sidecar_child
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        if guard.is_some() {
            return Err("VPN is already running".into());
        }
    }

    // Kill any stale sidecar processes that might hold the WinTUN adapter
    kill_all_sidecar_processes();
    // Give OS a moment to release the adapter
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    app.emit("vpn-log", VpnLogPayload {
        message: "Spawning trusttunnel_client process...".into(),
        level: "info".into(),
    }).ok();

    // Reset flags for new connection
    if let Ok(mut d) = state.disconnecting.lock() { *d = false; }
    if let Ok(mut c) = state.is_connected.lock() { *c = false; }

    // Pass Arc clones so sidecar can clear itself on termination
    let child_arc = Arc::clone(&state.sidecar_child);
    let disc_arc = Arc::clone(&state.disconnecting);
    let conn_arc = Arc::clone(&state.is_connected);

    // Always use at least "info" for sidecar — "Successfully connected to endpoint"
    // is an INFO message; suppressing it breaks connection status detection.
    let sidecar_log_level = match log_level.as_str() {
        "error" | "warn" => "info",
        other => other,
    };

    let child = sidecar::spawn_trusttunnel(&app, &config_path, sidecar_log_level, child_arc, disc_arc, conn_arc)
        .await
        .map_err(|e| {
            let msg = format!("Failed to start sidecar: {e}");
            eprintln!("[vpn_connect] {msg}");
            app.emit("vpn-log", VpnLogPayload {
                message: msg.clone(),
                level: "error".into(),
            }).ok();
            msg
        })?;

    eprintln!("[vpn_connect] Sidecar spawned OK, storing child handle");
    app.emit("vpn-log", VpnLogPayload {
        message: "Sidecar process started successfully".into(),
        level: "info".into(),
    }).ok();

    // Re-acquire lock to store child
    {
        let mut guard = state
            .sidecar_child
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        *guard = Some(child);
    }

    // Status stays "connecting" until sidecar detects "Successfully connected to endpoint"
    app.emit(
        "vpn-status",
        VpnStatusPayload {
            status: "connecting".into(),
            error: None,
        },
    )
    .ok();

    Ok(())
}

#[tauri::command]
async fn vpn_disconnect(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Take child out and drop guard before async call
    let child = {
        let mut guard = state
            .sidecar_child
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        guard.take()
    };

    if let Some(child) = child {
        // Signal intentional disconnect before killing
        if let Ok(mut d) = child.disconnecting.lock() { *d = true; }
        if let Ok(mut d) = state.disconnecting.lock() { *d = true; }
        sidecar::kill_sidecar(child)
            .await
            .map_err(|e| format!("Failed to stop sidecar: {e}"))?;
    }

    app.emit(
        "vpn-status",
        VpnStatusPayload {
            status: "disconnected".into(),
            error: None,
        },
    )
    .ok();

    Ok(())
}

#[tauri::command]
async fn test_sidecar(
    app: tauri::AppHandle,
) -> Result<String, String> {
    eprintln!("[test_sidecar] Spawning sidecar with -v flag...");
    let result = sidecar::spawn_with_args(&app, &["-v"])
        .await
        .map_err(|e| {
            let msg = format!("Failed to run sidecar: {e}");
            eprintln!("[test_sidecar] {msg}");
            msg
        })?;
    eprintln!("[test_sidecar] Got response: {result}");

    // Emit each line as a vpn-log event so it shows in the LogPanel
    for line in result.lines() {
        app.emit(
            "vpn-log",
            VpnLogPayload {
                message: line.to_string(),
                level: "info".to_string(),
            },
        )
        .ok();
    }

    Ok(result)
}

#[tauri::command]
async fn deploy_server(
    app: tauri::AppHandle,
    host: String,
    port: u16,
    user: String,
    password: String,
    settings: ssh_deploy::EndpointSettings,
) -> Result<String, String> {
    ssh_deploy::deploy_server(&app, host, port, user, password, settings).await
}

#[tauri::command]
fn check_vpn_status(state: tauri::State<'_, AppState>) -> String {
    let guard = state.sidecar_child.lock().unwrap();
    if guard.is_some() {
        let connected = state.is_connected.lock().map(|g| *g).unwrap_or(false);
        if connected { "connected" } else { "connecting" }.to_string()
    } else {
        "disconnected".to_string()
    }
}

#[tauri::command]
async fn diagnose_server(
    app: tauri::AppHandle,
    host: String,
    port: u16,
    user: String,
    password: String,
) -> Result<String, String> {
    ssh_deploy::diagnose_server(&app, host, port, user, password).await
}

#[tauri::command]
fn check_process_conflict() -> Option<String> {
    ssh_deploy::check_process_conflict()
}

#[tauri::command]
fn kill_existing_process() -> Result<(), String> {
    ssh_deploy::kill_existing_process()
}

#[tauri::command]
async fn check_server_installation(
    app: tauri::AppHandle,
    host: String,
    port: u16,
    user: String,
    password: String,
) -> Result<serde_json::Value, String> {
    ssh_deploy::check_server_installation(&app, host, port, user, password).await
}

#[tauri::command]
async fn uninstall_server(
    app: tauri::AppHandle,
    host: String,
    port: u16,
    user: String,
    password: String,
) -> Result<(), String> {
    ssh_deploy::uninstall_server(&app, host, port, user, password).await
}

#[tauri::command]
fn read_client_config(config_path: String) -> Result<serde_json::Value, String> {
    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config: {e}"))?;
    let table: toml::Value = content.parse()
        .map_err(|e| format!("Failed to parse TOML: {e}"))?;
    // Convert toml::Value to serde_json::Value
    let json = serde_json::to_value(&table)
        .map_err(|e| format!("Failed to convert: {e}"))?;
    Ok(json)
}

#[tauri::command]
fn save_client_config(config_path: String, config: serde_json::Value) -> Result<(), String> {
    // Convert JSON back to toml::Value then serialize
    let toml_val: toml::Value = serde_json::from_value(config)
        .map_err(|e| format!("Failed to convert config: {e}"))?;
    let content = toml::to_string_pretty(&toml_val)
        .map_err(|e| format!("Failed to serialize TOML: {e}"))?;
    std::fs::write(&config_path, &content)
        .map_err(|e| format!("Failed to write config: {e}"))?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Second instance launched — focus existing window instead
            if let Some(w) = app.get_webview_window("main") {
                w.show().ok();
                w.set_focus().ok();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_window_state::Builder::new().build())
        .manage(AppState {
            sidecar_child: Arc::new(Mutex::new(None)),
            disconnecting: Arc::new(Mutex::new(false)),
            is_connected: Arc::new(Mutex::new(false)),
        })
        .setup(|app| {
            // Build tray context menu
            let show_item = MenuItemBuilder::with_id("show", "Показать").build(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Выход").build(app)?;
            let tray_menu = MenuBuilder::new(app)
                .item(&show_item)
                .separator()
                .item(&quit_item)
                .build()?;

            // Create tray icon
            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("TrustTunnel-клиент")
                .menu(&tray_menu)
                .on_menu_event(|app, event| {
                    match event.id().as_ref() {
                        "show" => {
                            if let Some(w) = app.get_webview_window("main") {
                                w.show().ok();
                                w.set_focus().ok();
                            }
                        }
                        "quit" => {
                            // Kill sidecar + all stale processes before exiting
                            if let Some(state) = app.try_state::<AppState>() {
                                kill_sidecar_from_state(&state);
                            }
                            kill_all_sidecar_processes();
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            w.show().ok();
                            w.set_focus().ok();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            // Minimize to tray on close instead of quitting
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().ok();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            vpn_connect,
            vpn_disconnect,
            check_vpn_status,
            test_sidecar,
            deploy_server,
            diagnose_server,
            check_process_conflict,
            kill_existing_process,
            read_client_config,
            save_client_config,
            check_server_installation,
            uninstall_server
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                // Final cleanup: kill sidecar from state + any stale processes
                if let Some(state) = app.try_state::<AppState>() {
                    kill_sidecar_from_state(&state);
                }
                kill_all_sidecar_processes();
            }
        });
}
