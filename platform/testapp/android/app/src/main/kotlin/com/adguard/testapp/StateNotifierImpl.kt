package com.adguard.testapp

import FlutterCallbacks
import android.app.Activity
import android.content.Context
import com.adguard.trusttunnel.StateNotifier

class StateNotifierImpl (
    private val callbacks: FlutterCallbacks,
    private val activity: Activity
) : StateNotifier {
    override fun onStateChanged(state: Int) {
        activity.runOnUiThread {
            callbacks.onStateChanged(state.toLong()) {}
        }
    }
}