use std::process::Command;

/// Resolve the version, mirroring cmake/version.cmake's source order:
///   1. TT_CLIENT_VERSION environment variable (CI sets it once per job);
///   2. git describe --tags --match 'v*' (a plain local build is self-versioning);
///   3. 0.0.0-git fallback (never hard-fails the build).
fn resolve_version() -> String {
    if let Ok(v) = std::env::var("TT_CLIENT_VERSION") {
        let v = v.trim();
        if !v.is_empty() {
            return v.to_string();
        }
    }

    if let Ok(out) = Command::new("git")
        .args(["describe", "--tags", "--match", "v*"])
        .output()
    {
        if out.status.success() {
            let described = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !described.is_empty() {
                return described
                    .strip_prefix('v')
                    .unwrap_or(&described)
                    .to_string();
            }
        }
    }

    "0.0.0-git".to_string()
}

fn main() {
    // Re-run when the override or the resolved git state changes.
    println!("cargo:rerun-if-env-changed=TT_CLIENT_VERSION");
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    let full = resolve_version();

    // Inject into the crate so `env!("TT_CLIENT_VERSION")` (src/version.rs) works.
    println!("cargo:rustc-env=TT_CLIENT_VERSION={full}");
}
