#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Portable mode: store WebView2 data (localStorage, cache) next to the exe
    // instead of in AppData. Must be set BEFORE Tauri/WebView2 initializes.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let webview_data = dir.join("webview_data");
            std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", &webview_data);
        }
    }

    trusttunnel_lib::run()
}
