package com.adguard.trusttunnel

object DeepLink {

    init {
        System.loadLibrary("trusttunnel_android")
    }

    /**
     * Decode a `tt://` deep-link URI into a `[endpoint]` TOML section string.
     *
     * @param uri The `tt://...` deep-link URI to decode.
     * @return A TOML string beginning with `[endpoint]` that can be embedded
     *         in the full client configuration.
     * @throws RuntimeException if the URI is invalid or missing required fields.
     */
    @JvmStatic
    external fun decode(uri: String): String

    /**
     * Encode an `[endpoint]` TOML section string into a `tt://` deep-link URI.
     *
     * @param endpointToml A TOML string beginning with `[endpoint]`, in the
     *         same layout that [decode] produces.
     * @return The `tt://...` deep-link URI.
     * @throws RuntimeException if the TOML is invalid or missing required fields.
     */
    @JvmStatic
    external fun encode(endpointToml: String): String
}
