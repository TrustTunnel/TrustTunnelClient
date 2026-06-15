package com.adguard.trusttunnel.utils

import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import androidx.annotation.RequiresApi
import com.adguard.trusttunnel.Logger
import com.adguard.trusttunnel.VpnClient
import java.net.InetAddress
import java.text.MessageFormat
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

class NetworkUtils {
    companion object {
        private val LOG = Logger("NetworkUtils")

        class NetworkCollector : ConnectivityManager.NetworkCallback() {
            fun startNotifying(vpnClient: VpnClient?) {
                this.vpnClient = vpnClient
            }

            fun stopNotifying() {
                vpnClient = null
            }

            data class SystemDns (
                val servers: List<String>,
                val bootstraps: List<String>?
            )
            inner class NetworkProps {
                var type: Int = 0
                var systemDns: SystemDns? = null
            }
            private val availableNetworks = ConcurrentHashMap<Network, NetworkProps>()
            @Volatile
            private var vpnClient: VpnClient? = null

            override fun onLost(network: Network) {
                super.onLost(network)
                availableNetworks[network]?.apply {
                    availableNetworks.remove(network)
                    if (availableNetworks.isEmpty()) {
                        // No more networks available, notify as disconnected
                        vpnClient?.notifyNetworkChange(false)
                        return
                    }
                    val preferredNetwork = availableNetworks.values.maxBy { it.type }
                    // Update only if higher priority network lost
                    if (preferredNetwork.type < this.type) {
                        vpnClient?.notifyNetworkChange(true)
                        preferredNetwork.systemDns?.apply {
                            VpnClient.setSystemDnsServers(servers, bootstraps)
                        }
                    }
                }
            }

            // This call is guaranteed to be invoked immediately after onAvailable
            // so it is safe to add networks here
            // https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback#onCapabilitiesChanged(android.net.Network,%20android.net.NetworkCapabilities)
            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities
            ) {
                super.onCapabilitiesChanged(network, networkCapabilities)
                if (availableNetworks[network] != null) {
                    return
                }
                val oldType = availableNetworks.values.maxOfOrNull { it.type } ?: 0
                val newType = getNetworkType(networkCapabilities)
                availableNetworks[network] = NetworkProps()
                availableNetworks[network]?.type = newType
                if (vpnClient == null) {
                    return
                }
                if (newType > oldType) {
                    vpnClient?.notifyNetworkChange(true)
                }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                super.onLinkPropertiesChanged(network, linkProperties)

                val servers = getSystemDnsWithFallbacks(linkProperties)
                if (servers.isEmpty()) {
                    // Should never happened
                    return
                }
                val privateDns = getPrivateDns(linkProperties)

                val props = availableNetworks[network] ?: return

                val systemDns = if (privateDns != null) {
                    SystemDns(privateDns.toList(), servers.toList())
                } else {
                    SystemDns(servers.toList(), null)
                }
                // Update dns only if they have changed
                if (props.systemDns == systemDns) {
                    return
                }
                props.systemDns = systemDns

                if (props.type >= availableNetworks.values.maxOf{ it.type }) {
                    VpnClient.setSystemDnsServers(systemDns.servers, systemDns.bootstraps)
                }
            }

            private fun getNetworkType(capabilities: NetworkCapabilities): Int {
                return when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 4
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 3
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> 1
                    // Unknown transport that has connection to internet. Assume it as highest priority
                    else -> Int.MAX_VALUE
                }
            }
        }

        fun convertCidrToAddressPrefixPair(cidr: String): Pair<String, Int>? {
            try {
                val split = cidr.split('/')
                if (split.size == 2) {
                    val address = split[0]
                    val prefix = split[1].toInt()
                    return Pair(address, prefix)
                }
                throw Exception("Expected input in format: `ip/prefix`")
            } catch (e: Exception) {
                LOG.error("Failed to parse CIDR notation: $e")
                return null
            }
        }

        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        fun convertCidrToIpPrefix(cidr: String): IpPrefix? {
            try {
                val pair = convertCidrToAddressPrefixPair(cidr) ?: return null
                val inet = InetAddress.getByName(pair.first)
                return IpPrefix(inet, pair.second)
            } catch (e: Exception) {
                LOG.error("Failed to parse CIDR notation: $e")
                return null
            }
        }

        private val SYSTEM_DNS_FALLBACKS = arrayOf("8.8.8.8", "8.8.4.4")

        fun getSystemDnsWithFallbacks(linkProperties: LinkProperties): Array<String> {
            val servers = ArrayList<String>()
            for (server in linkProperties.dnsServers) {
                if (!server.isLoopbackAddress && !server.isLinkLocalAddress) {
                    val address = server.hostAddress
                    if (address != null) {
                        servers.add(address)
                    }
                }
            }
            return if (servers.isNotEmpty()) {
                servers.toTypedArray()
            } else {
                SYSTEM_DNS_FALLBACKS
            }
        }

        fun getPrivateDns(linkProperties: LinkProperties): Array<String>? {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (linkProperties.isPrivateDnsActive) {
                    val privateDns = linkProperties.privateDnsServerName
                    if (privateDns != null) {
                        return Collections.singletonList(MessageFormat.format("tls://{0}", privateDns)).toTypedArray()
                    }
                }
            }
            return null
        }
    }
}