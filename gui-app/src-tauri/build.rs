fn main() {
    // Use Tauri's own WindowsAttributes to embed requireAdministrator manifest.
    // This replaces Tauri's default asInvoker manifest so UAC prompt is shown on launch.
    #[cfg(windows)]
    {
        let windows_attrs = tauri_build::WindowsAttributes::new()
            .app_manifest(include_str!("trusttunnel.exe.manifest"));
        let attrs = tauri_build::Attributes::new()
            .windows_attributes(windows_attrs);
        tauri_build::try_build(attrs).expect("failed to run tauri build");
    }
    #[cfg(not(windows))]
    tauri_build::build();

    // Copy correct vcruntime DLLs to output dir (Miniconda ships older versions
    // that shadow System32 and cause STATUS_ENTRYPOINT_NOT_FOUND).
    // Also copy wintun.dll so the sidecar can find it at runtime.
    #[cfg(windows)]
    {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        // OUT_DIR is target/debug/build/<pkg>/out — go up 3 levels to target/debug
        let target_dir = out_dir.ancestors().nth(3).unwrap();

        let sys32 = std::path::Path::new(r"C:\Windows\System32");
        for dll in &["vcruntime140.dll", "vcruntime140_1.dll"] {
            let src = sys32.join(dll);
            let dst = target_dir.join(dll);
            if src.exists() && !dst.exists() {
                std::fs::copy(&src, &dst).ok();
            }
        }

        // Copy wintun.dll next to the sidecar binary
        let wintun_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wintun.dll");
        let wintun_dst = target_dir.join("wintun.dll");
        if wintun_src.exists() && !wintun_dst.exists() {
            std::fs::copy(&wintun_src, &wintun_dst).ok();
        }

        // Copy admin manifest so Windows requests elevation (TUN needs admin)
        let manifest_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("trusttunnel.exe.manifest");
        let manifest_dst = target_dir.join("trusttunnel.exe.manifest");
        if manifest_src.exists() {
            std::fs::copy(&manifest_src, &manifest_dst).ok();
        }
    }
}
