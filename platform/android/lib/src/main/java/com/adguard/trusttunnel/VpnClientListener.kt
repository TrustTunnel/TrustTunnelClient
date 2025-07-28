package com.adguard.trusttunnel

interface VpnClientListener {
    fun protectSocket(socket: Int): Boolean;
    fun verifyCertificate(certificate: ByteArray?, rawChain: List<ByteArray?>?): Boolean;
    fun onStateChanged(state: Int);
}