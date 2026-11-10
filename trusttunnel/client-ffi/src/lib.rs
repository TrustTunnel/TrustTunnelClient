use std::ffi::CStr;
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

/// Run the TrustTunnel CLI client setup wizard.
///
/// # Safety
/// `argv` must point to `argc` valid C strings when `argc` is greater than zero.
#[no_mangle]
pub unsafe extern "C" fn trusttunnel_client_run_setup_wizard(
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    keep_deeplink_ffi_linked();

    if argc < 0 || (argc > 0 && argv.is_null()) {
        eprintln!("Invalid setup wizard arguments.");
        return 2;
    }

    let mut args = Vec::with_capacity(argc as usize);
    for index in 0..argc {
        let pointer = unsafe { *argv.add(index as usize) };
        if pointer.is_null() {
            eprintln!("Invalid setup wizard argument.");
            return 2;
        }
        let value = match unsafe { CStr::from_ptr(pointer) }.to_str() {
            Ok(value) => value,
            Err(_) => {
                eprintln!("Setup wizard arguments must be valid UTF-8.");
                return 2;
            }
        };
        args.push(value.to_string());
    }

    match catch_unwind(AssertUnwindSafe(|| {
        setup_wizard::run_from_args(PROGRAM, args)
    })) {
        Ok(code) => code,
        Err(_) => {
            eprintln!("The setup wizard terminated unexpectedly.");
            101
        }
    }
}
