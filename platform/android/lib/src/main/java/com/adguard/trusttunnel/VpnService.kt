package com.adguard.trusttunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.adguard.trusttunnel.log.LoggerManager
import com.adguard.trusttunnel.utils.NetworkUtils
import com.adguard.trusttunnel.utils.concurrent.thread.ThreadManager

class VpnService : android.net.VpnService(), VpnClientListener {

    companion object {
        private val SYNC = Any()

        private val LOG = LoggerManager.getLogger("VpnService")

        // Network monitoring
        private lateinit var connectivityManager: ConnectivityManager
        private lateinit var networkRequest: NetworkRequest
        private lateinit var networkCallback: NetworkUtils.Companion.NetworkCollector

        private var vpnClient: VpnClient? = null

        private const val ACTION_START = "Start"
        private const val ACTION_STOP  = "Stop"
        private const val PARAM_CONFIG = "Config Extra"
        private const val NOTIFICATION_ID = 1

        private fun start(context: Context, intent: Intent, config: String?) {
            try {
                config?.apply {
                    intent.putExtra(PARAM_CONFIG, config)
                }
                context.startService(intent)
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

        private var stateNotifier: StateNotifier? = null;
        fun setStateNotifier(notifier: StateNotifier) {
            stateNotifier = notifier;
        }
    }

    private var state = State.Ready
    private val singleThread = ThreadManager.create("vpn-service", 1)
    private var certificateVerificator: CertificateVerificator? = null


    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = synchronized(SYNC) {
        if (state == State.Stopped) {
            LOG.error("VPN service has been already stopped, can't do anything with it")
            return START_NOT_STICKY
        }

        if (intent == null) {
            LOG.info("Received a null intent, doing nothing")
            stopSelf()
            return START_NOT_STICKY
        }

        // We run all payload in another thread (not main) to minimize UI lags
        singleThread.execute {
            val action = intent.action
            val config = intent.getStringExtra(PARAM_CONFIG)
            LOG.info("Start executing action=$action flags=$flags startId=$startId")
            when (action) {
                ACTION_START    -> processStarting(config)
                ACTION_STOP     -> close()
                else            -> LOG.info("Unknown command $action")
            }

            LOG.info("Command $action for the VPN has been executed")
        }

        return START_NOT_STICKY
    }

    private fun processStarting(configStr: String?): Unit = synchronized(SYNC) {
        if (state == State.Stopped) {
            LOG.info("VPN service has already been stopped, do nothing")
            return
        }
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

        val notification = createNotification(this.applicationContext)
        startForeground(NOTIFICATION_ID, notification)

        vpnClient = VpnClient(configStr, this)

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
        try {
            val builder = Builder().setSession("Trust Tunnel")
                .setMtu(config.mtuSize.toInt())
                .addAddress("172.20.2.13", 32)
                .addAddress("fdfd:29::2", 64)
                .addDnsServer("94.140.14.140")
                .addDnsServer("94.140.14.141")
                .addDisallowedApplication(applicationContext.packageName)

            config.excludedRoutes.forEach { route ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val r = NetworkUtils.convertCidrToIpPrefix(route)
                    if (r != null) {
                        builder.excludeRoute(r)
                    } else {
                        throw Exception("Wrong syntax for excluded_routes")
                    }
                } else {
                    LOG.info("Ignoring excluded route for Android versions less than 13 (Tiramisu): $route")
                }
            }

            config.includedRoutes.forEach { route ->
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
     *
     * @return true if the service has been closed successfully
     *         false if something is wrong with closing or the service has already been closed
     */
    private fun close(): Boolean = synchronized(SYNC) {
        if (state != State.Started) return false.also { LOG.info("VPN service is not running, do nothing") }

        LOG.info("Closing VPN service")

        networkCallback.stopNotifying()
        vpnClient?.stop()
        vpnClient?.close()
        vpnClient = null
        singleThread.shutdown()
        stopSelf()
        state = State.Stopped

        LOG.info("VPN service closed!")
        return true
    }

    /** An enum to represent the VPN service states */
    enum class State {
        Ready, Started, Stopped
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

    override fun onStateChanged(state: Int) {
        LOG.info("OnStateChanged: $state")
        stateNotifier?.onStateChanged(state)
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
            .setContentText("Vpn is running in foreground") // Content text of the notification
            // Use a small icon that represents your VPN service.
            .setSmallIcon(android.R.drawable.ic_dialog_info) // Placeholder icon (replace with your app's icon)
            .setPriority(NotificationCompat.PRIORITY_LOW) // Set priority for older Android versions
            .setOngoing(true) // Makes the notification non-dismissible by the user.
            // This is a key characteristic of foreground service notifications.
            .build()
    }
}