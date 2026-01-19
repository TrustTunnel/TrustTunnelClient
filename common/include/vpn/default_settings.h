#pragma once

/** Default state for post-quantum group in TLS handshakes (enabled by default) */
#define VPN_DEFAULT_POST_QUANTUM_GROUP_ENABLED true
/** Default state for handler profiling (disabled by default) */
#define VPN_DEFAULT_HANDLER_PROFILING_ENABLED false

/**
 * Default settings for vpn.
 */
struct VpnDefaultSettings {
    bool post_quantum_group_enabled;    /**< Default state for post-quantum group in TLS handshakes */
    bool handler_profiling_enabled;     /**< Default state for handler profiling */
};
