package com.adguard.trusttunnel

import com.adguard.trusttunnel.log.LoggerManager
import com.akuleshov7.ktoml.Toml
import com.akuleshov7.ktoml.TomlInputConfig
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
class VpnServiceConfig (
    @SerialName("included_routes")
    val includedRoutes: List<String>,
    @SerialName("excluded_routes")
    val excludedRoutes: List<String>,
    @SerialName("mtu_size")
    val mtuSize: Long
) {
    companion object {
        private val LOG = LoggerManager.getLogger("VpnServiceConfig")
        fun parseToml(config: String): VpnServiceConfig? {
            try {
                val toml = Toml(
                    inputConfig = TomlInputConfig(
                        ignoreUnknownNames = true,
                        allowEmptyValues = false,
                        allowNullValues = true,
                    )
                )
                return toml.partiallyDecodeFromString<VpnServiceConfig>(
                    serializer(),
                    config,
                    "listener.tun"
                )
            } catch (e: Exception) {
                LOG.error("Failed to parse config: $e");
                return null;
            }
        }
    }
}