package com.adguard.trusttunnel

object Subscription {

    init {
        System.loadLibrary("trusttunnel_android")
    }

    /**
     * Fetch the subscription document from the URL stored in the `[endpoint.subscription]`
     * table and merge it back into the endpoint configuration.
     *
     * @param endpointToml A TOML string beginning with `[endpoint]` that holds an
     *         `[endpoint.subscription]` section with the subscription URL.
     * @return The updated TOML string beginning with `[endpoint]`, with the fetched
     *         subscription parameters applied, or `null` on any failure. Blocks until
     *         the request completes.
     */
    @JvmStatic
    external fun fetchAndApply(endpointToml: String): String?
}
