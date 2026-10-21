package com.adguard.trusttunnel

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*

@RunWith(AndroidJUnit4::class)
class DeepLinkInstrumentedTest {
    init {
        System.loadLibrary("trusttunnel_android")
    }

    @Test
    fun decode_is_correct() {
        val decodedConfig: String = DeepLink.decode(KNOWN_URI)

        expectKnownEndpoint(decodedConfig)
        assertTrue(decodedConfig.contains("-----BEGIN CERTIFICATE-----"))
    }

    @Test
    fun encode_is_correct() {
        val uri: String = DeepLink.encode(ENDPOINT_TOML)

        assertTrue(uri.startsWith("tt://"))
        val decodedConfig: String = DeepLink.decode(uri)

        expectKnownEndpoint(decodedConfig)
        assertEquals("Example VPN", getQuoted(decodedConfig, "name"))
        assertEquals(listOf("tls://dns.adguard-dns.com"), getArray(decodedConfig, "dns_upstreams"))
    }

    @Test
    fun encode_decode_roundtrip() {
        val endpointToml: String = DeepLink.decode(KNOWN_URI)
        val uri: String = DeepLink.encode(endpointToml)

        assertTrue(uri.startsWith("tt://"))
        expectKnownEndpoint(DeepLink.decode(uri))
    }

    private fun expectKnownEndpoint(config: String) {
        assertEquals("localhost", getQuoted(config, "hostname"))
        assertEquals("test", getQuoted(config, "username"))
        assertEquals("test", getQuoted(config, "password"))
        assertEquals("aabb", getQuoted(config, "client_random"))
        assertEquals("http2", getQuoted(config, "upstream_protocol"))
        assertEquals("localhost", getQuoted(config, "custom_sni"))

        assertTrue(getBool(config, "has_ipv6"))
        assertFalse(getBool(config, "skip_verification"))
        assertFalse(getBool(config, "anti_dpi"))

        assertEquals(listOf("127.0.0.1:4443"), getArray(config, "addresses"))
    }

    private fun getQuoted(config: String, name: String): String {
        val re = Regex("""(?m)^\s*$name\s*=\s*"([^"]*)"""")
        val v = re.find(config)?.groupValues?.get(1)
            ?: fail("Field $name not found in:\n$config")
        return v.toString()
    }

    private fun getBool(config: String, name: String): Boolean {
        val re = Regex("""(?m)^\s*$name\s*=\s*(true|false)\s*$""")
        val v = re.find(config)?.groupValues?.get(1)
            ?: fail("Field $name not found in:\n$config")
        return v.toString().toBooleanStrict()
    }

    private fun getArray(config: String, name: String): List<String> {
        val re = Regex("""\b$name\s*=\s*\[(.*?)]""", RegexOption.DOT_MATCHES_ALL)
        val inside = re.find(config)?.groupValues?.get(1)
            ?: fail("Field $name not found in\n$config")
        return Regex(""""([^"]*)"""").findAll(inside.toString()).map { it.groupValues[1] }
            .toList()
    }

    private companion object {
        const val KNOWN_URI =
            "tt://AQlsb2NhbGhvc3QFBHRlc3QGBHRlc3QCDjEyNy4wLjAuMTo0NDQzCwRhYWJiAwlsb2NhbGhvc3QIQVMwggFPMIH1oAMCAQICFGi8WMY2yFmtW2u_18hMQBa0T4VGMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjAxMzAwMDAwMDBaFw0yNzAxMzAwMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB4ozK9KbqScCCTJ8CvTfW4W0r9OEsn4VcQswd-BbP9z-tdyfE5HT4uHLUSZRWUKfZjnRRkHWOwhp9KJhOE-LAWjJTAjMCEGA1UdEQQaMBiCCWxvY2FsaG9zdIILKi5sb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAO6gFBHDsgvWjPj39JNchcMF3X2ICgzycBwTyydxqpdiAiEAgybYwECuZopK1g6JX5tK0-5B3Of7n0NuPXRGSU5TtSc"

        const val ENDPOINT_TOML = "[endpoint]\n" +
            "hostname = \"localhost\"\n" +
            "addresses = [\"127.0.0.1:4443\"]\n" +
            "username = \"test\"\n" +
            "password = \"test\"\n" +
            "client_random = \"aabb\"\n" +
            "custom_sni = \"localhost\"\n" +
            "name = \"Example VPN\"\n" +
            "dns_upstreams = [\"tls://dns.adguard-dns.com\"]\n"
    }
}
