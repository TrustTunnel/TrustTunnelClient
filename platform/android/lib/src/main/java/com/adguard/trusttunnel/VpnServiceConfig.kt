package com.adguard.trusttunnel

import com.akuleshov7.ktoml.Toml
import com.akuleshov7.ktoml.TomlInputConfig
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
class Tun (
    @SerialName("included_routes")
    val includedRoutes: List<String>,
    @SerialName("excluded_routes")
    val excludedRoutes: List<String>,
    @SerialName("mtu_size")
    val mtuSize: Long
)

@Serializable
class Listener (
    val tun: Tun
)

@Serializable
class Endpoint (
    @SerialName("dns_upstreams")
    val dnsUpstreams: List<String> = emptyList()
)

@Serializable
class VpnServiceConfig (
    val listener: Listener,
    val endpoint: Endpoint
) {
    companion object {
        private val LOG = Logger("VpnServiceConfig")
        fun parseToml(config: String): VpnServiceConfig? {
            try {
                val toml = Toml(
                    inputConfig = TomlInputConfig(
                        ignoreUnknownNames = true,
                        allowEmptyValues = false,
                        allowNullValues = true,
                    )
                )
                return toml.decodeFromString(
                    serializer(),
                    config
                )
            } catch (e: Exception) {
                LOG.error("Failed to parse config: $e");
                return null;
            }
        }
    }
}