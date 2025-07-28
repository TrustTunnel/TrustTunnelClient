package com.adguard.trusttunnel

interface StateNotifier {
    fun onStateChanged(state: Int);
}