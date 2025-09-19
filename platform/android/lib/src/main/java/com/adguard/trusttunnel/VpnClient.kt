package com.adguard.trusttunnel

import android.os.ParcelFileDescriptor
import com.adguard.trusttunnel.log.LoggerManager
import com.adguard.trusttunnel.log.NativeLogger
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
            NativeLogger
        }
        private val LOG = LoggerManager.getLogger("VpnClient")
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
            LOG.error("Can't stop native client because it was not created")
            return;
        }
        stopNative(nativePtr);
    }

    fun notifyNetworkChange(available: Boolean) = synchronized(sync) {
        if (nativePtr.toInt() == 0) {
            LOG.error("Can't call notifyNetworkChange, native client is not initialized")
            return;
        }
        notifyNetworkChangeNative(nativePtr, available);
    }

    fun setSystemDnsServers(servers: Array<String>, bootstraps: Array<String>?): Boolean = synchronized(sync) {
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

    // Native methods
    private external fun createNative(config: String): Long;
    private external fun startNative(nativePtr: Long, tunFd: Int): Boolean;
    private external fun stopNative(nativePtr: Long);
    private external fun notifyNetworkChangeNative(nativePtr: Long, available: Boolean);
    private external fun setSystemDnsServersNative(servers: Array<String>, bootstraps: Array<String>?): Boolean
    private external fun destroyNative(nativePtr: Long);
}