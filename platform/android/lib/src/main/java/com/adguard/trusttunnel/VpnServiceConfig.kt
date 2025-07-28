package com.adguard.trusttunnel

import com.adguard.trusttunnel.log.LoggerManager
import com.akuleshov7.ktoml.Toml
import com.akuleshov7.ktoml.TomlInputConfig
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

class VpnServiceConfig (
    val certificateConfig: CertificateVerificatorConfig,
    val tunConfig: TunConfig
) {
    @Serializable
    class CertificateVerificatorConfig (
        val certificate: String? = null,
        @SerialName("skip_verification")
        val skipVerification: Boolean
    )

    @Serializable
    class TunConfig (
        @SerialName("included_routes")
        val includedRoutes: List<String>,
        @SerialName("excluded_routes")
        val excludedRoutes: List<String>,
        @SerialName("mtu_size")
        val mtuSize: Long
    )
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
                val tunConfig = toml.partiallyDecodeFromString<TunConfig>(
                    TunConfig.serializer(),
                    config,
                    "listener.tun"
                )

                val certificateConfig = toml.partiallyDecodeFromString<CertificateVerificatorConfig>(
                    CertificateVerificatorConfig.serializer(),
                    config,
                    "endpoint"
                )

                return VpnServiceConfig(certificateConfig, tunConfig)
            } catch (e: Exception) {
                LOG.error("Failed to parse config: $e");
                return null;
            }
        }
    }
}