#ifndef TRUSTTUNNEL_CLIENT_FFI_H
#define TRUSTTUNNEL_CLIENT_FFI_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Run the setup wizard.
//
// `args` is a NUL-separated argument list. Each argument, including the last,
// is followed by a NUL byte. `args_len` is the total byte length.
int trusttunnel_client_run_setup_wizard(const char *args, size_t args_len);

#ifdef __cplusplus
}
#endif

#endif
