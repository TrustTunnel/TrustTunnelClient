//! C ABI for the subscription primitives, consumed by `trusttunnel_client`
//! and callable from platform adapters. `panic = "abort"` makes any panic
//! fatal to the host process, so nothing here may panic: all inputs are
//! validated and all errors are returned.

use std::ffi::{c_char, c_int, CStr, CString};

/// Heap-allocated error handed to the caller; free with
/// [`trusttunnel_subscription_error_free`].
pub struct SubscriptionFfiError {
    message: CString,
}

fn make_error(message: String) -> *mut SubscriptionFfiError {
    // A message with interior NULs cannot round-trip through CString; fall
    // back to a fixed string rather than panicking.
    let message =
        CString::new(message).unwrap_or_else(|_| CString::new("subscription failure").unwrap());
    Box::into_raw(Box::new(SubscriptionFfiError { message }))
}

fn fail(error: *mut *mut SubscriptionFfiError, message: String) -> c_int {
    if !error.is_null() {
        unsafe { *error = make_error(message) };
    }
    1
}

fn cstr_arg<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("{name} is null"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| format!("{name} is not valid UTF-8"))
}

fn cstr_opt<'a>(ptr: *const c_char, name: &str) -> Result<Option<&'a str>, String> {
    if ptr.is_null() {
        return Ok(None);
    }
    cstr_arg(ptr, name).map(Some)
}

fn outcome_string(
    result: Result<String, String>,
    out: *mut *mut c_char,
    error: *mut *mut SubscriptionFfiError,
) -> c_int {
    let string = match result {
        Ok(string) => string,
        Err(message) => return fail(error, message),
    };
    if out.is_null() {
        return fail(error, "output parameter is null".to_string());
    }
    match CString::new(string) {
        Ok(string) => {
            unsafe { *out = string.into_raw() };
            0
        }
        Err(_) => fail(error, "result contains an interior NUL byte".to_string()),
    }
}

fn outcome_unit(result: Result<(), String>, error: *mut *mut SubscriptionFfiError) -> c_int {
    match result {
        Ok(()) => 0,
        Err(message) => fail(error, message),
    }
}

/// Fetch the subscription document at `url` and hand the raw validated JSON
/// body back in `*out_json` (free with [`trusttunnel_subscription_string_free`]).
/// `certificate_pem` optionally pins the server certificate; when
/// `certificate_host` is non-null the pin applies only if the URL's host
/// matches it, when null the pin always applies. Blocks for the duration of
/// the request. Returns 0 on success, 1 on failure; the error message never
/// contains the URL or credentials.
///
/// # Safety
/// `url`, `certificate_host` and `certificate_pem` must be null or valid
/// NUL-terminated C strings; `out_json` and `error` must be null or point to
/// writable memory for one pointer.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_subscription_fetch(
    url: *const c_char,
    certificate_host: *const c_char,
    certificate_pem: *const c_char,
    skip_verification: c_int,
    out_json: *mut *mut c_char,
    error: *mut *mut SubscriptionFfiError,
) -> c_int {
    if !error.is_null() {
        unsafe { *error = std::ptr::null_mut() };
    }
    if !out_json.is_null() {
        unsafe { *out_json = std::ptr::null_mut() };
    }
    let result = (|| -> Result<String, String> {
        let url = cstr_arg(url, "url")?;
        let certificate_host = cstr_opt(certificate_host, "certificate host")?;
        let certificate_pem = cstr_opt(certificate_pem, "certificate")?;
        trusttunnel_subscription::fetch_subscription_json(
            url,
            certificate_host,
            certificate_pem,
            skip_verification != 0,
            &trusttunnel_subscription::UreqTransport,
        )
        .map_err(|e| e.to_string())
    })();
    outcome_string(result, out_json, error)
}

/// Fetch the subscription document for the endpoint described by the
/// endpoint TOML fragment (a document with an `[endpoint]` table) and hand
/// the raw validated JSON body back in `*out_json` (free with
/// [`trusttunnel_subscription_string_free`]). The subscription URL, the
/// certificate pin (gated by the endpoint hostname) and the verification
/// policy are read from the endpoint. Blocks for the duration of the
/// request. Returns 0 on success, 1 on failure; the error message never
/// contains the URL or credentials.
///
/// # Safety
/// `endpoint_toml` must be null or a valid NUL-terminated C string;
/// `out_json` and `error` must be null or point to writable memory for one
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_subscription_fetch_for_endpoint(
    endpoint_toml: *const c_char,
    out_json: *mut *mut c_char,
    error: *mut *mut SubscriptionFfiError,
) -> c_int {
    if !error.is_null() {
        unsafe { *error = std::ptr::null_mut() };
    }
    if !out_json.is_null() {
        unsafe { *out_json = std::ptr::null_mut() };
    }
    let result = (|| -> Result<String, String> {
        let endpoint_toml = cstr_arg(endpoint_toml, "endpoint toml")?;
        trusttunnel_subscription::fetch_for_endpoint(
            endpoint_toml,
            &trusttunnel_subscription::UreqTransport,
        )
        .map_err(|e| e.to_string())
    })();
    outcome_string(result, out_json, error)
}

/// Merge the subscription document (as returned by
/// [`trusttunnel_subscription_fetch`]) into the endpoint TOML fragment and
/// hand the updated fragment back in `*out_endpoint` (free with
/// [`trusttunnel_subscription_string_free`]). Everything the model does not
/// represent — comments, key order, unknown keys — is preserved. Returns 0
/// on success, 1 on failure.
///
/// # Safety
/// `endpoint_toml` and `subscription_json` must be null or valid
/// NUL-terminated C strings; `out_endpoint` and `error` must be null or
/// point to writable memory for one pointer.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_subscription_apply_endpoint(
    endpoint_toml: *const c_char,
    subscription_json: *const c_char,
    out_endpoint: *mut *mut c_char,
    error: *mut *mut SubscriptionFfiError,
) -> c_int {
    if !error.is_null() {
        unsafe { *error = std::ptr::null_mut() };
    }
    if !out_endpoint.is_null() {
        unsafe { *out_endpoint = std::ptr::null_mut() };
    }
    let result = (|| -> Result<String, String> {
        let endpoint_toml = cstr_arg(endpoint_toml, "endpoint toml")?;
        let subscription_json = cstr_arg(subscription_json, "subscription json")?;
        trusttunnel_subscription::apply_endpoint(endpoint_toml, subscription_json)
            .map_err(|e| e.to_string())
    })();
    outcome_string(result, out_endpoint, error)
}

/// Extract the `[endpoint]` subtree of the config text as a standalone TOML
/// document and hand it back in `*out_endpoint` (free with
/// [`trusttunnel_subscription_string_free`]). The subtree keeps its comments
/// and unknown keys. Returns 0 on success, 1 on failure.
///
/// # Safety
/// `config_text` must be null or a valid NUL-terminated C string;
/// `out_endpoint` and `error` must be null or point to writable memory for
/// one pointer.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_subscription_extract_endpoint(
    config_text: *const c_char,
    out_endpoint: *mut *mut c_char,
    error: *mut *mut SubscriptionFfiError,
) -> c_int {
    if !error.is_null() {
        unsafe { *error = std::ptr::null_mut() };
    }
    if !out_endpoint.is_null() {
        unsafe { *out_endpoint = std::ptr::null_mut() };
    }
    let result = (|| -> Result<String, String> {
        let config_text = cstr_arg(config_text, "config text")?;
        trusttunnel_subscription::extract_endpoint(config_text).map_err(|e| e.to_string())
    })();
    outcome_string(result, out_endpoint, error)
}

/// Replace the config's `[endpoint]` subtree with the one from the endpoint
/// fragment and hand the updated config back in `*out_config` (free with
/// [`trusttunnel_subscription_string_free`]). Everything else in the config
/// — comments, key order, unknown keys — is preserved. Returns 0 on success,
/// 1 on failure.
///
/// # Safety
/// `config_text` and `endpoint_toml` must be null or valid NUL-terminated C
/// strings; `out_config` and `error` must be null or point to writable
/// memory for one pointer.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_subscription_replace_endpoint(
    config_text: *const c_char,
    endpoint_toml: *const c_char,
    out_config: *mut *mut c_char,
    error: *mut *mut SubscriptionFfiError,
) -> c_int {
    if !error.is_null() {
        unsafe { *error = std::ptr::null_mut() };
    }
    if !out_config.is_null() {
        unsafe { *out_config = std::ptr::null_mut() };
    }
    let result = (|| -> Result<String, String> {
        let config_text = cstr_arg(config_text, "config text")?;
        let endpoint_toml = cstr_arg(endpoint_toml, "endpoint toml")?;
        trusttunnel_subscription::replace_endpoint(config_text, endpoint_toml)
            .map_err(|e| e.to_string())
    })();
    outcome_string(result, out_config, error)
}

/// Replace the file at `path` with `content` atomically, preserving the
/// original permission mode. The file must already exist — it is never
/// created. Returns 0 on success, 1 on failure.
///
/// # Safety
/// `path` and `content` must be null or valid NUL-terminated C strings;
/// `error` must be null or point to writable memory for one pointer.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_subscription_replace_file_atomic(
    path: *const c_char,
    content: *const c_char,
    error: *mut *mut SubscriptionFfiError,
) -> c_int {
    if !error.is_null() {
        unsafe { *error = std::ptr::null_mut() };
    }
    let result = (|| -> Result<(), String> {
        let path = cstr_arg(path, "path")?;
        let content = cstr_arg(content, "content")?;
        trusttunnel_subscription::replace_file_atomic(path, content).map_err(|e| e.to_string())
    })();
    outcome_unit(result, error)
}

/// Free a string returned in `out_json`, `out_endpoint` or `out_config`.
/// Safe to call with null.
///
/// # Safety
/// `string` must be null or a pointer previously returned in an
/// out-parameter of this library, passed at most once.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_subscription_string_free(string: *mut c_char) {
    if !string.is_null() {
        drop(unsafe { CString::from_raw(string) });
    }
}

/// Borrow the diagnostic of an error object. The pointer stays valid until
/// [`trusttunnel_subscription_error_free`].
///
/// # Safety
/// `error` must be a pointer previously returned in the error out-parameter
/// of a function in this library.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_subscription_error_message(
    error: *const SubscriptionFfiError,
) -> *const c_char {
    if error.is_null() {
        return c"unknown error".as_ptr();
    }
    unsafe { (*error).message.as_ptr() }
}

/// Free an error object. Safe to call with null.
///
/// # Safety
/// `error` must be null or a pointer previously returned in the error
/// out-parameter of a function in this library, passed at most once.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_subscription_error_free(error: *mut SubscriptionFfiError) {
    if !error.is_null() {
        drop(unsafe { Box::from_raw(error) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "# keep me\n[endpoint]\nhostname = \"old.example.com\"\naddresses = [\"1.1.1.1:443\"]\nusername = \"alice\"\npassword = \"old\"\n[endpoint.subscription]\nurl = \"https://old.example.com/subscription\"\n[listener.socks]\naddress = \"127.0.0.1:1080\"\n";
    const ENDPOINT: &str = "# keep me\n[endpoint]\nhostname = \"old.example.com\"\naddresses = [\"1.1.1.1:443\"]\nusername = \"alice\"\npassword = \"old\"\n[endpoint.subscription]\nurl = \"https://old.example.com/subscription\"\n";
    const BODY: &str = r#"{"version":1,"hostname":"new.example.com","address":"5.6.7.8:443","username":"bob","password":"hunter2","has_ipv6":true,"upstream_protocol":"http3","anti_dpi":false,"skip_verification":false}"#;

    fn take_string(ptr: *mut c_char) -> String {
        let value = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        unsafe { trusttunnel_subscription_string_free(ptr) };
        value
    }

    fn error_message(error: *mut SubscriptionFfiError) -> String {
        let message = unsafe { CStr::from_ptr(trusttunnel_subscription_error_message(error)) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe { trusttunnel_subscription_error_free(error) };
        message
    }

    #[test]
    fn fetch_null_url_is_an_error_not_a_crash() {
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_fetch(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                &mut out,
                &mut error,
            )
        };
        assert_eq!(code, 1);
        assert!(out.is_null());
        assert!(error_message(error).contains("null"));
    }

    #[test]
    fn endpoint_fetch_null_endpoint_is_an_error_not_a_crash() {
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_fetch_for_endpoint(std::ptr::null(), &mut out, &mut error)
        };
        assert_eq!(code, 1);
        assert!(out.is_null());
        assert!(error_message(error).contains("null"));
    }

    #[test]
    fn endpoint_fetch_without_subscription_is_a_distinct_error() {
        let endpoint = CString::new(
            "[endpoint]\nhostname = \"h\"\naddresses = [\"1.1.1.1:443\"]\nusername = \"a\"\npassword = \"p\"\n",
        )
        .unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_fetch_for_endpoint(endpoint.as_ptr(), &mut out, &mut error)
        };
        assert_eq!(code, 1);
        assert!(out.is_null());
        assert_eq!(error_message(error), "No subscription URL configured.");
    }

    #[test]
    fn endpoint_fetch_with_invalid_endpoint_is_a_parse_error() {
        let endpoint = CString::new("not [valid toml").unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_fetch_for_endpoint(endpoint.as_ptr(), &mut out, &mut error)
        };
        assert_eq!(code, 1);
        assert!(out.is_null());
        assert!(error_message(error).contains("Failed to parse endpoint"));
    }

    #[test]
    fn apply_merges_and_returns_the_updated_endpoint() {
        let endpoint = CString::new(ENDPOINT).unwrap();
        let body = CString::new(BODY).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_apply_endpoint(
                endpoint.as_ptr(),
                body.as_ptr(),
                &mut out,
                &mut error,
            )
        };
        assert_eq!(code, 0);
        assert!(error.is_null());
        let updated = take_string(out);
        assert!(updated.contains("hostname = \"new.example.com\""));
        assert!(updated.contains("last_fetched_at"));
        assert!(updated.contains("# keep me"));
        assert!(!updated.contains("[listener]"), "unexpected: {updated}");
    }

    #[test]
    fn apply_invalid_document_is_an_error() {
        let endpoint = CString::new(ENDPOINT).unwrap();
        let body = CString::new(BODY.replace("\"version\":1", "\"version\":2")).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_apply_endpoint(
                endpoint.as_ptr(),
                body.as_ptr(),
                &mut out,
                &mut error,
            )
        };
        assert_eq!(code, 1);
        assert!(out.is_null());
        assert!(error_message(error).contains("upgrade"));
    }

    #[test]
    fn apply_null_endpoint_is_an_error() {
        let body = CString::new(BODY).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_apply_endpoint(
                std::ptr::null(),
                body.as_ptr(),
                &mut out,
                &mut error,
            )
        };
        assert_eq!(code, 1);
        assert!(out.is_null());
        assert!(error_message(error).contains("null"));
    }

    #[test]
    fn extract_returns_the_endpoint_subtree() {
        let config = CString::new(CONFIG).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_extract_endpoint(config.as_ptr(), &mut out, &mut error)
        };
        assert_eq!(code, 0);
        assert!(error.is_null());
        let fragment = take_string(out);
        assert!(fragment.contains("hostname = \"old.example.com\""));
        assert!(fragment.contains("[endpoint.subscription]"));
        assert!(!fragment.contains("[listener]"), "unexpected: {fragment}");
    }

    #[test]
    fn extract_null_config_is_an_error() {
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_extract_endpoint(std::ptr::null(), &mut out, &mut error)
        };
        assert_eq!(code, 1);
        assert!(out.is_null());
        assert!(error_message(error).contains("null"));
    }

    #[test]
    fn replace_swaps_the_endpoint_and_preserves_the_config() {
        let config = CString::new(CONFIG).unwrap();
        let endpoint =
            CString::new(ENDPOINT.replace("old.example.com", "new.example.com")).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_replace_endpoint(
                config.as_ptr(),
                endpoint.as_ptr(),
                &mut out,
                &mut error,
            )
        };
        assert_eq!(code, 0);
        assert!(error.is_null());
        let updated = take_string(out);
        assert!(updated.contains("hostname = \"new.example.com\""));
        assert!(updated.contains("# keep me"));
        assert!(updated.contains("[listener.socks]"));
    }

    #[test]
    fn replace_null_endpoint_is_an_error() {
        let config = CString::new(CONFIG).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_replace_endpoint(
                config.as_ptr(),
                std::ptr::null(),
                &mut out,
                &mut error,
            )
        };
        assert_eq!(code, 1);
        assert!(out.is_null());
        assert!(error_message(error).contains("null"));
    }

    #[test]
    fn replace_missing_file_is_an_error_not_a_creation() {
        let dir = std::env::temp_dir().join(format!("ffi-write-missing-{}", std::process::id()));
        let path_buf = dir.join("nope.toml");
        let path = CString::new(path_buf.to_str().unwrap()).unwrap();
        let content = CString::new("x").unwrap();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_replace_file_atomic(
                path.as_ptr(),
                content.as_ptr(),
                &mut error,
            )
        };
        assert_eq!(code, 1);
        assert!(!path_buf.exists());
        unsafe { trusttunnel_subscription_error_free(error) };
    }

    #[test]
    fn replace_writes_content_and_preserves_mode() {
        let dir = std::env::temp_dir().join(format!("ffi-write-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path_buf = dir.join("config.toml");
        std::fs::write(&path_buf, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path_buf, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let path = CString::new(path_buf.to_str().unwrap()).unwrap();
        let content = CString::new("new").unwrap();
        let mut error: *mut SubscriptionFfiError = std::ptr::null_mut();
        let code = unsafe {
            trusttunnel_subscription_replace_file_atomic(
                path.as_ptr(),
                content.as_ptr(),
                &mut error,
            )
        };
        assert_eq!(code, 0);
        assert_eq!(std::fs::read_to_string(&path_buf).unwrap(), "new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path_buf).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn string_free_accepts_null() {
        unsafe { trusttunnel_subscription_string_free(std::ptr::null_mut()) };
    }
}
