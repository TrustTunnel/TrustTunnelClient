use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use serde::Serialize;
use trusttunnel_settings::{endpoint_from_deeplink_config, Endpoint};

#[derive(Serialize)]
struct EndpointWrapper {
    endpoint: Endpoint,
}

fn decode_to_endpoint_toml(uri: &str) -> Result<String, String> {
    let config = trusttunnel_deeplink::decode(uri).map_err(|e| e.to_string())?;
    let endpoint = endpoint_from_deeplink_config(config)?;
    let wrapper = EndpointWrapper { endpoint };
    toml::to_string(&wrapper).map_err(|e| e.to_string())
}

/// Opaque error object. Free with `trusttunnel_deeplink_error_free`.
#[repr(C)]
pub struct DeepLinkError {
    message: *mut c_char,
}

impl DeepLinkError {
    fn new(msg: String) -> *mut Self {
        let message = CString::new(msg).unwrap_or_else(|_| CString::new("unknown error").unwrap());
        Box::into_raw(Box::new(DeepLinkError {
            message: message.into_raw(),
        }))
    }
}

/// Free an error returned by any `trusttunnel_deeplink_*` function.
/// Passing NULL is safe.
#[no_mangle]
pub extern "C" fn trusttunnel_deeplink_error_free(error: *mut DeepLinkError) {
    if !error.is_null() {
        unsafe {
            let e = Box::from_raw(error);
            drop(CString::from_raw(e.message));
        }
    }
}

/// Return the NULL-terminated error message. The pointer is valid until
/// `trusttunnel_deeplink_error_free` is called on `error`.
#[no_mangle]
pub extern "C" fn trusttunnel_deeplink_error_message(error: &DeepLinkError) -> *const c_char {
    error.message
}

/// Decode a `tt://` URI into a NULL-terminated `[endpoint]` TOML string.
///
/// On success, returns a heap-allocated string the caller MUST free with
/// `trusttunnel_deeplink_string_free`.
/// On failure, returns NULL and writes a heap-allocated `DeepLinkError`
/// into `*error` (if `error` is non-NULL). Free it with
/// `trusttunnel_deeplink_error_free`.
#[no_mangle]
pub extern "C" fn trusttunnel_deeplink_decode(
    uri: *const c_char,
    error: *mut *mut DeepLinkError,
) -> *mut c_char {
    let write_error = |msg: String| {
        if !error.is_null() {
            unsafe { *error = DeepLinkError::new(msg) };
        }
    };

    if uri.is_null() {
        write_error("URI pointer is null".to_string());
        return std::ptr::null_mut();
    }

    let uri_str = unsafe {
        match CStr::from_ptr(uri).to_str() {
            Ok(s) => s,
            Err(e) => {
                write_error(format!("Invalid UTF-8 in URI: {}", e));
                return std::ptr::null_mut();
            }
        }
    };

    match decode_to_endpoint_toml(uri_str) {
        Ok(toml_str) => match CString::new(toml_str) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                write_error(format!("TOML output contains null byte: {}", e));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            write_error(e);
            std::ptr::null_mut()
        }
    }
}

/// Free a string returned by `trusttunnel_deeplink_decode`.
/// Passing NULL is safe.
#[no_mangle]
pub extern "C" fn trusttunnel_deeplink_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use trusttunnel_deeplink::{DeepLinkConfig, Protocol};

    #[test]
    fn test_decode_invalid_scheme() {
        let result = decode_to_endpoint_toml("http://example.com");
        assert!(result.is_err(), "Should reject non-tt:// URIs");
    }

    #[test]
    fn test_decode_empty_string() {
        let result = decode_to_endpoint_toml("");
        assert!(result.is_err(), "Should reject empty string");
    }

    #[test]
    fn test_decode_tt_scheme_empty_payload() {
        let result = decode_to_endpoint_toml("tt://");
        assert!(result.is_err(), "Should reject empty payload");
    }

    #[test]
    fn test_ffi_null_input() {
        let mut error: *mut DeepLinkError = std::ptr::null_mut();
        let ptr = trusttunnel_deeplink_decode(std::ptr::null(), &mut error);
        assert!(ptr.is_null(), "Should return NULL for null input");
        assert!(!error.is_null(), "Should set error for null input");
        trusttunnel_deeplink_error_free(error);
    }

    #[test]
    fn test_ffi_null_error_param() {
        let ptr = trusttunnel_deeplink_decode(std::ptr::null(), std::ptr::null_mut());
        assert!(
            ptr.is_null(),
            "Should return NULL for null input even without error param"
        );
    }

    #[test]
    fn test_ffi_free_does_not_panic_on_null() {
        trusttunnel_deeplink_string_free(std::ptr::null_mut());
        trusttunnel_deeplink_error_free(std::ptr::null_mut());
    }

    #[test]
    fn test_roundtrip() {
        let config = DeepLinkConfig {
            hostname: "vpn.example.com".to_string(),
            addresses: vec!["1.2.3.4:443".parse::<SocketAddr>().unwrap()],
            username: "alice".to_string(),
            password: "s3cr3t".to_string(),
            client_random_prefix: Some("aabb".to_string()),
            custom_sni: None,
            has_ipv6: true,
            skip_verification: false,
            certificate: None,
            upstream_protocol: Protocol::Http2,
            anti_dpi: false,
        };

        let uri = trusttunnel_deeplink::encode(&config).expect("encode should succeed");
        let toml_str = decode_to_endpoint_toml(&uri).expect("round-trip decode should succeed");

        assert!(
            toml_str.contains("[endpoint]"),
            "Output must contain [endpoint] header"
        );
        assert!(
            toml_str.contains("hostname"),
            "Output must contain hostname field"
        );
        assert!(
            toml_str.contains("vpn.example.com"),
            "Output must contain the hostname value"
        );
        assert!(toml_str.contains("alice"), "Output must contain username");
        assert!(
            toml_str.contains("aabb"),
            "Output must contain client_random"
        );
    }
}
