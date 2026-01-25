package com.adguard.trusttunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.adguard.trusttunnel.db.ConnectionLog
import com.adguard.trusttunnel.db.ConnectionLogDatabase
import com.adguard.trusttunnel.log.LoggerManager
import com.adguard.trusttunnel.utils.NetworkUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class VpnService : android.net.VpnService(), VpnClientListener {

    companion object {
        private val LOG = LoggerManager.getLogger("VpnService")

        // Network monitoring
        private lateinit var connectivityManager: ConnectivityManager
        private lateinit var networkRequest: NetworkRequest
        private lateinit var networkCallback: NetworkUtils.Companion.NetworkCollector
        
        // Removed: connectionInfoFile (replaced by DB)
        // Removed: currentStartId (lifecycle managed by Service)

        private var vpnClient: VpnClient? = null
        
        // The last VpnState observed by `onStateChanged`
        private var lastState: Int = 0
        private const val ACTION_START = "Start"
        private const val ACTION_STOP  = "Stop"
        private const val PARAM_CONFIG = "Config Extra"
        private const val NOTIFICATION_ID = 1
        
        // TODO: Move these to config/constants file
        private val IPV4_NON_ROUTABLE = listOf("0.0.0.0/8", "224.0.0.0/3")
        private val ADGUARD_DNS_SERVERS = listOf("46.243.231.30", "46.243.231.31", "2a10:50c0::2:ff", "2a10:50c0::1:ff")
        private val FAKE_DNS_SERVER = listOf("198.18.53.53")

        private fun start(context: Context, intent: Intent, config: String?) {
            try {
                if (!isPrepared(context)) {
                    LOG.warn("VPN is not prepared, can't manipulate the service")
                    return
                }
                config?.apply {
                    intent.putExtra(PARAM_CONFIG, config)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (e: Exception) {
                LOG.error("Error occurred while service starting", e)
            }
        }

        fun stop(context: Context)                  = start(context, ACTION_STOP, null)
        fun start(context: Context, config: String?) = start(context, ACTION_START, config)
        private fun start(context: Context, action: String, config: String?) = start(context, getIntent(context, action), config)

        fun startNetworkManager(context: Context) {
            connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            networkRequest = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .addTransportType(NetworkCapabilities.TRANSPORT_BLUETOOTH)
                .build()

            networkCallback = NetworkUtils.Companion.NetworkCollector()
            connectivityManager.registerNetworkCallback(networkRequest, networkCallback)
        }

        fun isPrepared(context: Context): Boolean {
            return try {
                prepare(context) == null
            } catch (e: Exception) {
                LOG.error("Error while checking VPN service is prepared", e)
                false
            }
        }

        /** Gets an intent instance with [action] */
        private fun getIntent(context: Context, action: String): Intent = Intent(context, VpnService::class.java).setAction(action)
        
        private var appNotifier: AppNotifier? = null
        
        fun setAppNotifier(notifier: AppNotifier) {
            appNotifier = notifier
            // Notify current state immediately
            appNotifier?.onStateChanged(lastState)
            // Note: DB logs are now pulled via DAO Flow in UI, not pushed here
        }
    }

    private var state = State.Stopped
    
    // Coroutine Scope for the service
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    private var certificateVerificator: CertificateVerificator? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            LOG.info("Received a null intent, doing nothing")
            stopSelf()
            return START_NOT_STICKY
        }

        // Foreground service must spawn its notification in the first 5 seconds of the service lifetime
        val notification = createNotification(this.applicationContext)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID, 
                    notification, 
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_VIRTUAL_MEETING // More appropriate for standard VPN than SYSTEM_EXEMPTED
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            LOG.error("Failed to start foreground service", e)
             // Fallback to standard startForeground if specific type fails (though Q+ requires type logic)
             if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                 // Try generic if VIRTUAL_MEETING fails (or match manifest)
                 // Assuming Manifest has FOREGROUND_SERVICE_DATA_SYNC or similar
             }
        }

        serviceScope.launch {
            try {
                val action = intent.action
                val config = intent.getStringExtra(PARAM_CONFIG)
                LOG.info("Start executing action=$action flags=$flags startId=$startId")
                when (action) {
                    ACTION_START    -> processStarting(config)
                    ACTION_STOP     -> close()
                    else            -> LOG.info("Unknown command $action")
                }

                LOG.info("Command $action for the VPN has been executed")
            } catch (e: Exception) {
                LOG.error("Error while executing command", e)
            }
        }

        return START_NOT_STICKY
    }
    
    private suspend fun processStarting(configStr: String?) {
        if (state == State.Started) {
            LOG.info("VPN service has already been started, do nothing")
            return
        }
        if (configStr == null) {
            LOG.error("Failed to get the Vpn Interface config settings")
            return
        }
        val config = VpnServiceConfig.parseToml(configStr)
        if (config == null) {
            LOG.error("Failed to parse Vpn Interface config")
            return
        }

        try {
            certificateVerificator = CertificateVerificator()
        } catch (e: Exception) {
            LOG.error("Failed to create certificate verifier: $e")
            close()
            return
        }

        LOG.info("VPN is starting...")
        val vpnTunInterface = createTunInterface(config) ?: run {
            close()
            return
        }
        
        val service = this
        val proxyClientListener = object : VpnClientListener by service {
            override fun onStateChanged(state: Int) {
                try {
                    val vpnState = VpnState.getByCode(state)
                    LOG.info("VpnService onStateChanged: ${vpnState.name}")
                    if (vpnState == VpnState.DISCONNECTED) {
                        serviceScope.launch {
                            service.close()
                        }
                    }
                } catch (e: Exception) {
                    LOG.warn("Failed to process unknown VPN state $state: $e")
                }
                service.onStateChanged(state)
            }
        }
        vpnClient = VpnClient(configStr, proxyClientListener)

        networkCallback.startNotifying(vpnClient)
        if (vpnClient?.start(vpnTunInterface) != true) {
            LOG.error("Failed to start Vpn client");
            close();
        }

        state = State.Started
    }

    override fun onRevoke() {
        serviceScope.launch {
            LOG.info("Revoking the VPN service")
            close()
        }
    }
    
    // Cleanup on destroy
    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }

    private fun createTunInterface(config: VpnServiceConfig): ParcelFileDescriptor? {
        LOG.info("Request 'create tun interface' received")
        val tunConfig = config.listener.tun
        try {
            val builder = Builder().setSession("Trust Tunnel")
                .setMtu(tunConfig.mtuSize.toInt())
                .addAddress("172.20.2.13", 32)
                .addAddress("fdfd:29::2", 64)
                .addDisallowedApplication(applicationContext.packageName)
            val dnsServers = if (config.dnsUpstreams.isEmpty()) {
                ADGUARD_DNS_SERVERS
            } else {
                FAKE_DNS_SERVER
            }
            dnsServers.forEach { server ->
                builder.addDnsServer(server)
            }
            // TODO: Avoid hardcoded routes logic if possible, fetch from config
            val routes = VpnClient.excludeCidr(tunConfig.includedRoutes, tunConfig.excludedRoutes + IPV4_NON_ROUTABLE)
                ?: throw Exception("Failed to process routes")
            routes.forEach { route ->
                val r = NetworkUtils.convertCidrToAddressPrefixPair(route)
                if (r != null) {
                    builder.addRoute(r.first, r.second)
                } else {
                    throw Exception("Wrong syntax for included_routes")
                }
            }

            return builder.establish()

        } catch (e: Exception) {
            LOG.error("Error while building the TUN interface", e)
            return null
        }
    }

    /**
     * Closes the VPN TUN interface and stops itself
     */
    private suspend fun close(): Boolean = withContext(Dispatchers.IO) {
        if (state != State.Started) {
            LOG.info("VPN service is not running, do nothing")
            return@withContext false
        }

        LOG.info("Closing VPN service")

        networkCallback.stopNotifying()
        vpnClient?.stop()
        vpnClient?.close()
        vpnClient = null
        stopSelf()
        state = State.Stopped

        LOG.info("VPN service closed!")
        return@withContext true
    }

    /** An enum to represent the VPN service states */
    enum class State {
        Started, Stopped
    }

    // Pass-through to super
    override fun protectSocket(socket: Int): Boolean {
        if (protect(socket)) {
            LOG.info("The socket $socket has been protected successfully")
            return true
        }
        LOG.info("Failed to protect socket $socket")
        return false
    }

    override fun verifyCertificate(certificate: ByteArray?, rawChain: List<ByteArray?>?): Boolean {
        return certificateVerificator?.verifyCertificate(certificate, rawChain) ?: false;
    }

    override fun onStateChanged(state: Int) {
        serviceScope.launch {
            lastState = state
            appNotifier?.onStateChanged(state)
        }
    }

    override fun onConnectionInfo(info: String) {
        serviceScope.launch {
            LOG.debug("VpnService onConnectionInfo event")
            try {
                // Persist to Room Database
                val db = ConnectionLogDatabase.getDatabase(applicationContext)
                db.connectionLogDao().insert(ConnectionLog(data = info))
                // Clean up old logs (optional optimization, could be done periodically instead)
                // db.connectionLogDao().prune() 
            } catch (e: Exception) {
                LOG.error("Failed to write connection info to DB", e)
            }
            appNotifier?.onConnectionInfo(info)
        }
    }

    private fun createNotification(context: Context): Notification {
        val name = "ConnectionStatus"
        val descriptionText = "VPN connection status"
        val channel = NotificationChannel(
            name,
            descriptionText,
            NotificationManager.IMPORTANCE_LOW 
        ).apply {
            description = "TrustTunnel status" 
        }
        val notificationManager: NotificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(channel)
        return NotificationCompat.Builder(context, name)
            .setContentTitle("TrustTunnel") 
            .setContentText("VPN is running in foreground") 
            .setSmallIcon(android.R.drawable.ic_dialog_info) 
            .setPriority(NotificationCompat.PRIORITY_LOW) 
            .setOngoing(true)
            .build()
    }
}