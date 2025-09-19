package com.adguard.trusttunnel

import com.adguard.trusttunnel.log.LoggerManager
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class CertificateVerificator {
    private val certificateFactory: CertificateFactory
    private val trustManagerFactory: TrustManagerFactory
    companion object {
        private val LOG = LoggerManager.getLogger("CertificateVerificator")
    }
    init {
        try {
            this.certificateFactory = CertificateFactory.getInstance("X.509")
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)

            val tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm()
            this.trustManagerFactory = TrustManagerFactory.getInstance(tmfAlgorithm)
            trustManagerFactory.init(keyStore)
        } catch (e: CertificateException) {
            throw KeyStoreException(e)
        } catch (e: IOException) {
            throw KeyStoreException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyStoreException(e)
        }
    }

    fun verifyCertificate(certificate: ByteArray?, rawChain: List<ByteArray?>?): Boolean {
        try {
            val chain: MutableList<X509Certificate> = ArrayList()
            chain.add(
                certificateFactory.generateCertificate(
                    ByteArrayInputStream(certificate)
                ) as X509Certificate
            )
            for (cert in rawChain!!) {
                chain.add(certificateFactory.generateCertificate(ByteArrayInputStream(cert)) as X509Certificate)
            }

            for (tm in trustManagerFactory.trustManagers) {
                val xtm = tm as X509TrustManager
                xtm.checkServerTrusted(chain.toTypedArray(), "UNKNOWN")
            }

            return true // Success
        } catch (e: Exception) {
            LOG.error("Failed to verify certificate: $e")
            return false // Failure
        }
    }
}