package com.adguard.trusttunnel

import android.os.ParcelFileDescriptor
import com.adguard.trusttunnel.log.LoggerManager
import com.adguard.trusttunnel.log.NativeLogger
import com.adguard.trusttunnel.log.NativeLoggerLevel
import java.io.Closeable

class VpnClient (
    private val config: String,
    private val callbacks: VpnClientListener?
) : Closeable {
    companion object {
        init {
            System.loadLibrary("trusttunnel_android")
            // Kotlin objects are lazy initialized so call here to
            // ensure it is initialized.
            NativeLogger.defaultLogLevel = NativeLoggerLevel.INFO
        }
        private val LOG = LoggerManager.getLogger("VpnClient")

        fun excludeCidr(includedRoutes: List<String>, excludedRoutes: List<String>): List<String>? {
            return excludeCidr(includedRoutes.toTypedArray(), excludedRoutes.toTypedArray())?.toList()
        }
        @JvmStatic
        private external fun excludeCidr(includedRoutes: Array<String>, excludedRoutes: Array<String>): Array<String>?
    }
    private var nativePtr: Long = 0
    private val sync = Any()

    fun start(vpnTunInterface: ParcelFileDescriptor?): Boolean = synchronized(sync) {
        nativePtr = createNative(config)
        if (nativePtr.toInt() == 0) {
            LOG.error("Failed to create a native client")
            return false
        }

        return startNative(nativePtr, vpnTunInterface?.detachFd() ?: -1)
    }

    fun stop() = synchronized(sync) {
        if (nativePtr.toInt() == 0) {
            LOG.warn("Can't stop native client because it was not created or already closed")
            return;
        }
        try {
            stopNative(nativePtr)
        } catch (e: Exception) {
            LOG.error("Error stopping native client", e)
        }
    }

    fun notifyNetworkChange(available: Boolean) = synchronized(sync) {
        if (nativePtr.toInt() == 0) {
            LOG.warn("Skipping notifyNetworkChange, native client is not initialized")
            return;
        }
        notifyNetworkChangeNative(nativePtr, available)
    }

    fun setSystemDnsServers(servers: Array<String>, bootstraps: Array<String>?): Boolean = synchronized(sync) {
        if (nativePtr.toInt() == 0) {
            return false
        }
        return setSystemDnsServersNative(servers, bootstraps)
    }

    override fun close() = synchronized(sync) {
        if (nativePtr.toInt() != 0) {
            destroyNative(nativePtr);
        }
    }

    // These are called from native code
    fun protectSocket(socket: Int): Boolean {
        return callbacks?.protectSocket(socket) ?: false
    }
    fun verifyCertificate(certificate: ByteArray?, rawChain: List<ByteArray?>?): Boolean {
        return callbacks?.verifyCertificate(certificate, rawChain) ?: false
    }
    fun onStateChanged(state: Int) {
        callbacks?.onStateChanged(state)
    }

    fun onConnectionInfo(info: String) {
        callbacks?.onConnectionInfo(info)
    }

    // Native methods
    private external fun createNative(config: String): Long;
    private external fun startNative(nativePtr: Long, tunFd: Int): Boolean;
    private external fun stopNative(nativePtr: Long);
    private external fun notifyNetworkChangeNative(nativePtr: Long, available: Boolean);
    private external fun setSystemDnsServersNative(servers: Array<String>, bootstraps: Array<String>?): Boolean
    private external fun destroyNative(nativePtr: Long);
}