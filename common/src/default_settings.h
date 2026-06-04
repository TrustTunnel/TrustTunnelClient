#pragma once

/** Default state for post-quantum group in TLS handshakes (enabled by default) */
#define VPN_DEFAULT_POST_QUANTUM_GROUP_ENABLED true
/** Default state for handler profiling (disabled by default) */
#define VPN_DEFAULT_HANDLER_PROFILING_ENABLED false
/** Default state for TCP early ACK for exclusions (disabled by default) */
#define VPN_DEFAULT_EXCLUSIONS_TCP_EARLY_ACK_ENABLED false
/** Default state for pre-resolving exclusions in background (enabled by default) */
#define VPN_DEFAULT_EXCLUSIONS_PRERESOLVE_ENABLED true
/** Default max number of exclusion domains to pre-resolve per cycle (default 50) */
#define VPN_DEFAULT_EXCLUSIONS_PRERESOLVE_MAX_QUERIES 50
