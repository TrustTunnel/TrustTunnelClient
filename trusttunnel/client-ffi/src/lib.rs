use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};

const PROGRAM: &str = "trusttunnel_client --setup-wizard";

// The C++ client links this archive for both APIs. Reference the deeplink
// entry points so the linker keeps them in the combined static library.
fn keep_deeplink_ffi_linked() {
    std::hint::black_box(trusttunnel_deeplink_ffi::trusttunnel_deeplink_decode);
    std::hint::black_box(trusttunnel_deeplink_ffi::trusttunnel_deeplink_encode);
    std::hint::black_box(trusttunnel_deeplink_ffi::trusttunnel_deeplink_error_free);
    std::hint::black_box(trusttunnel_deeplink_ffi::trusttunnel_deeplink_error_message);
    std::hint::black_box(trusttunnel_deeplink_ffi::trusttunnel_deeplink_string_free);
}

fn run_from_serialized(serialized: &str) -> i32 {
    let args = serialized
        .split_terminator('\0')
        .map(ToOwned::to_owned)
        .collect();
    setup_wizard::run_from_args(PROGRAM, args)
}

fn finish(run: impl FnOnce() -> i32) -> c_int {
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(code) => code,
        Err(_) => {
            eprintln!("The setup wizard terminated unexpectedly.");
            101
        }
    }
}

/// Run the TrustTunnel CLI client setup wizard.
///
/// `args` is a NUL-separated argument list. Each argument, including the last,
/// is followed by a NUL byte. `args_len` is the total byte length.
///
/// # Safety
/// `args` must point to `args_len` readable bytes when `args_len` is nonzero.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_client_run_setup_wizard(
    args: *const c_char,
    args_len: usize,
) -> c_int {
    keep_deeplink_ffi_linked();

    if args_len == 0 {
        return finish(|| run_from_serialized(""));
    }

    if args.is_null() {
        eprintln!("Invalid setup wizard arguments.");
        return 2;
    }

    let bytes = unsafe { std::slice::from_raw_parts(args.cast::<u8>(), args_len) };
    let serialized = match std::str::from_utf8(bytes) {
        Ok(serialized) => serialized,
        Err(_) => {
            eprintln!("Setup wizard arguments must be valid UTF-8.");
            return 2;
        }
    };

    finish(|| run_from_serialized(serialized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_from_serialized_args() {
        assert_eq!(run_from_serialized("--help\0"), 0);
    }

    #[test]
    fn invalid_mode_from_serialized_args() {
        assert_ne!(run_from_serialized("--mode\0invalid\0"), 0);
    }
}
