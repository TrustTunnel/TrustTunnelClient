// The version string is resolved at build time by build.rs (TT_CLIENT_VERSION
// env override -> git describe -> 0.0.0-git) and injected via cargo:rustc-env.
pub const VERSION: &str = env!("TT_CLIENT_VERSION");
