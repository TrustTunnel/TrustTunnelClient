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
import com.adguard.trusttunnel.log.LoggerManager
import com.adguard.trusttunnel.utils.NetworkUtils
import com.adguard.trusttunnel.utils.concurrent.thread.ThreadManager
import java.io.File

class VpnService : android.net.VpnService(), VpnClientListener {

    companion object {
        private val SYNC = Any()

        private val LOG = LoggerManager.getLogger("VpnService")

        // Network monitoring
        private lateinit var connectivityManager: ConnectivityManager
        private lateinit var networkRequest: NetworkRequest
        private lateinit var networkCallback: NetworkUtils.Companion.NetworkCollector
        private var connectionInfoFile: PrefixedLenRingProto? = null
        private var currentStartId: Int = -1

        private var vpnClient: VpnClient? = null
        private var configStorage: VpnConfigStorage? = null
        // The last VpnState observed by `onStateChanged`
        private var lastState: Int = 0
        private const val ACTION_START = "Start"
        private const val ACTION_STOP  = "Stop"
        private const val PARAM_CONFIG = "Config Extra"
        private const val NOTIFICATION_ID = 1
        private val IPV4_NON_ROUTABLE = listOf("0.0.0.0/8", "224.0.0.0/3")
        private val ADGUARD_DNS_SERVERS = listOf("46.243.231.30", "46.243.231.31", "2a10:50c0::2:ff", "2a10:50c0::1:ff")
        private val FAKE_DNS_SERVER = listOf("198.18.53.53")

        private fun getConfigStorage(context: Context): VpnConfigStorage {
            return configStorage ?: VpnConfigStorage(context).also { configStorage = it }
        }

        private fun start(context: Context, intent: Intent, config: String?) {
            try {
                if (!isPrepared(context)) {
                    LOG.warn("VPN is not prepared, can't manipulate the service")
                    return
                }
                config?.apply {
                    getConfigStorage(context).save(config)
                    intent.putExtra(PARAM_CONFIG, config)
                }
                context.startForegroundService(intent)
            } catch (e: Exception) {
                LOG.error("Error occurred while service starting", e)
            }
        }

        fun stop(context: Context) {
            getConfigStorage(context).clear()
            start(context, ACTION_STOP, null)
        }
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

        private val eventsSync = ThreadManager.create("events-sync", 1)
        private var appNotifier: AppNotifier? = null;
        fun setAppNotifier(file: File, notifier: AppNotifier) {
            connectionInfoFile = PrefixedLenRingProto(file)
            appNotifier = notifier
            eventsSync.execute {
                // Notify current state
                appNotifier?.onStateChanged(lastState)
                // Notify all query logs
                connectionInfoFile?.apply {
                    val records = read_all()
                    if (records == null) {
                        clear()
                        return@execute
                    }
                    for (record in records) {
                        appNotifier?.onConnectionInfo(record)
                    }
                }
            }
        }
    }

    private var state = State.Stopped
    private val singleThread = ThreadManager.create("vpn-service", 1)
    private var certificateVerificator: CertificateVerificator? = null


    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = synchronized(SYNC) {
        val action: String?
        val config: String?
        if (intent == null || (intent.action == null && intent.getStringExtra(PARAM_CONFIG) == null)) {
            LOG.info("System-triggered start (Always-On VPN), loading persisted config")
            action = ACTION_START
            config = getConfigStorage(applicationContext).load()
        } else {
            action = intent.action
            config = intent.getStringExtra(PARAM_CONFIG)
        }

        // Foreground service must spawn its notification in the first 5 seconds of the service lifetime
        val notification = createNotification(this.applicationContext)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        // We run all payload in another thread (not main) to minimize UI lags
        singleThread.execute {
            try {
                currentStartId = startId
                LOG.info("Start executing action=$action flags=$flags startId=$startId")
                when (action) {
                    ACTION_START    -> processStarting(config, startId)
                    ACTION_STOP     -> close(startId)
                    else            -> LOG.info("Unknown command $action")
                }

                LOG.info("Command $action for the VPN has been executed")
            } catch (e: Exception) {
                LOG.error("Error while executing command", e)
            }
        }

        return START_NOT_STICKY
    }

    private fun processStarting(configStr: String?, startId: Int): Unit = synchronized(SYNC) {
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
            return run {
                close()
            }
        }

        LOG.info("VPN is starting...")
        val vpnTunInterface = createTunInterface(config) ?: return run {
            close()
        }
        // This is required to save startId and pass it to `closeIfLast` in case of DISCONNECTED state event
        val service = this
        val proxyClientListener = object : VpnClientListener by service {
            override fun onStateChanged(state: Int) {
                try {
                    val state = VpnState.getByCode(state)
                    LOG.info("VpnService onStateChanged: ${state.name}")
                    if (state == VpnState.DISCONNECTED) {
                        singleThread.execute {
                            service.closeIfLast(startId)
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

    override fun onRevoke() = singleThread.execute {
        LOG.info("Revoking the VPN service")
        close()
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
     * Closes the VPN TUN interface and stops itself only if the called is the only one who
     * tries to stop the service.
     * @param startId start id known to the caller
     * @return true if the service has been closed successfully
     *         false if the service hasn't been stopped because startId is too old
     */
    private fun closeIfLast(startId: Int): Boolean {
        if (startId < currentStartId) {
            return false
        }

        return close(startId)
    }

    /**
     * Closes the VPN TUN interface and stops itself
     * @param startId current start id of the service to forward to `stopSelf`
     * @return true if the service has been closed successfully
     *         false if something is wrong with closing or the service has already been closed
     */
    private fun close(startId: Int? = null): Boolean = synchronized(SYNC) {
        if (state != State.Started) return false.also { LOG.info("VPN service is not running, do nothing") }

        LOG.info("Closing VPN service")

        networkCallback.stopNotifying()
        vpnClient?.stop()
        vpnClient?.close()
        vpnClient = null
        if (startId != null) {
            stopSelf(startId)
        } else {
            stopSelf()
        }
        state = State.Stopped

        LOG.info("VPN service closed!")
        return true
    }

    /** An enum to represent the VPN service states */
    enum class State {
        Started, Stopped
    }

    /**
     * Protects passed socket by the [VpnService].
     * @param socket socket to protect
     * @return true if socket was protected or false if an error occurred
     */
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

    override fun onStateChanged(state: Int) = eventsSync.execute {
        lastState = state
        appNotifier?.onStateChanged(state)
    }

    override fun onConnectionInfo(info: String) = eventsSync.execute {
        LOG.debug("VpnService onConnectionInfo event")
        connectionInfoFile?.apply {
            if (!append(info)) {
                clear()
            }
        }
        appNotifier?.onConnectionInfo(info)
    }

    private fun createNotification(context: Context): Notification {
        val name = "ConnectionStatus"
        val descriptionText = "VPN connection status"
        val channel = NotificationChannel(
            name,
            descriptionText,
            NotificationManager.IMPORTANCE_LOW // Set importance to LOW to be less intrusive, but still visible.
        ).apply {
            description = "TrustTunnel status" // User-visible description of the channel
        }
        val notificationManager: NotificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(channel)
        return NotificationCompat.Builder(context, name)
            .setContentTitle("TrustTunnel") // Main title of the notification
            .setContentText("VPN is running in foreground") // Content text of the notification
            // Use a small icon that represents your VPN service.
            .setSmallIcon(android.R.drawable.ic_dialog_info) // Placeholder icon (replace with your app's icon)
            .setPriority(NotificationCompat.PRIORITY_LOW) // Set priority for older Android versions
            .setOngoing(true) // Makes the notification non-dismissible by the user.
            // This is a key characteristic of foreground service notifications.
            .build()
    }
}