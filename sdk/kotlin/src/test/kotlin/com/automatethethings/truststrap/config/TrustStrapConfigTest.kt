package com.automatethethings.truststrap.config

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TrustStrapConfigTest {

    @Test
    fun `default config has no enabled methods`() {
        val config = TrustStrapConfig()
        assertTrue(config.getEnabledMethods().isEmpty())
    }

    @Test
    fun `getEnabledMethods returns only enabled methods`() {
        val config = TrustStrapConfig(
            daneEnabled = true,
            noiseEnabled = false,
            spkiEnabled = true,
            directEnabled = false
        )
        val enabled = config.getEnabledMethods()
        assertEquals(2, enabled.size)
        assertEquals(BootstrapMethod.DANE, enabled[0])
        assertEquals(BootstrapMethod.SPKI, enabled[1])
    }

    @Test
    fun `getEnabledMethods respects method order`() {
        val config = TrustStrapConfig(
            daneEnabled = true,
            noiseEnabled = true,
            spkiEnabled = true,
            directEnabled = true,
            methodOrder = listOf(BootstrapMethod.DIRECT, BootstrapMethod.NOISE, BootstrapMethod.SPKI, BootstrapMethod.DANE)
        )
        val enabled = config.getEnabledMethods()
        assertEquals(BootstrapMethod.DIRECT, enabled[0])
        assertEquals(BootstrapMethod.NOISE, enabled[1])
        assertEquals(BootstrapMethod.SPKI, enabled[2])
        assertEquals(BootstrapMethod.DANE, enabled[3])
    }

    @Test
    fun `hasConfiguredMethod returns false when no methods have URLs`() {
        val config = TrustStrapConfig(daneEnabled = true)
        assertFalse(config.hasConfiguredMethod())
    }

    @Test
    fun `hasConfiguredMethod returns true for configured DANE`() {
        val config = TrustStrapConfig(
            daneEnabled = true,
            daneConfig = DANEConfig(serverUrl = "https://example.com")
        )
        assertTrue(config.hasConfiguredMethod())
    }

    @Test
    fun `hasConfiguredMethod returns true for configured Noise`() {
        val config = TrustStrapConfig(
            noiseEnabled = true,
            noiseConfig = NoiseConfig(serverAddress = "localhost:8445", serverStaticKey = "aa".repeat(32))
        )
        assertTrue(config.hasConfiguredMethod())
    }

    @Test
    fun `hasConfiguredMethod returns false for Noise with missing key`() {
        val config = TrustStrapConfig(
            noiseEnabled = true,
            noiseConfig = NoiseConfig(serverAddress = "localhost:8445", serverStaticKey = "")
        )
        assertFalse(config.hasConfiguredMethod())
    }

    @Test
    fun `hasConfiguredMethod returns true for configured SPKI`() {
        val config = TrustStrapConfig(
            spkiEnabled = true,
            spkiConfig = SPKIConfig(serverUrl = "https://example.com", spkiPinSha256 = "aa".repeat(32))
        )
        assertTrue(config.hasConfiguredMethod())
    }

    @Test
    fun `hasConfiguredMethod returns false for SPKI with missing pin`() {
        val config = TrustStrapConfig(
            spkiEnabled = true,
            spkiConfig = SPKIConfig(serverUrl = "https://example.com", spkiPinSha256 = "")
        )
        assertFalse(config.hasConfiguredMethod())
    }

    @Test
    fun `hasConfiguredMethod returns true for configured Direct`() {
        val config = TrustStrapConfig(
            directEnabled = true,
            directConfig = DirectConfig(serverUrl = "https://example.com")
        )
        assertTrue(config.hasConfiguredMethod())
    }

    @Test
    fun `deriveFromUrl populates all method configs from URL`() {
        val config = TrustStrapConfig().deriveFromUrl("https://kms.example.com:8443")
        assertEquals("https://kms.example.com:8443", config.daneConfig.serverUrl)
        assertEquals("kms.example.com:8445", config.noiseConfig.serverAddress)
        assertEquals("https://kms.example.com:8443", config.spkiConfig.serverUrl)
        assertEquals("https://kms.example.com:8443", config.directConfig.serverUrl)
    }

    @Test
    fun `deriveFromUrl uses default port 8443 when no port specified`() {
        val config = TrustStrapConfig().deriveFromUrl("https://kms.example.com")
        assertEquals("https://kms.example.com:8443", config.daneConfig.serverUrl)
        assertEquals("kms.example.com:8445", config.noiseConfig.serverAddress)
    }

    @Test
    fun `deriveFromUrl returns same config for blank URL`() {
        val original = TrustStrapConfig()
        val derived = original.deriveFromUrl("")
        assertEquals(original, derived)
    }

    @Test
    fun `deriveFromUrl returns same config for invalid URL`() {
        val original = TrustStrapConfig()
        val derived = original.deriveFromUrl("not a valid url %%%")
        assertEquals(original, derived)
    }

    @Test
    fun `default timeout is 15 seconds`() {
        val config = TrustStrapConfig()
        assertEquals(15, config.timeoutSeconds)
    }

    @Test
    fun `default method order is DANE, NOISE, SPKI, DIRECT`() {
        val config = TrustStrapConfig()
        assertEquals(BootstrapMethod.DEFAULT_ORDER, config.methodOrder)
        assertEquals(
            listOf(BootstrapMethod.DANE, BootstrapMethod.NOISE, BootstrapMethod.SPKI, BootstrapMethod.DIRECT),
            config.methodOrder
        )
    }

    @Test
    fun `BootstrapMethod fromName handles case insensitivity`() {
        assertEquals(BootstrapMethod.DANE, BootstrapMethod.fromName("dane"))
        assertEquals(BootstrapMethod.DANE, BootstrapMethod.fromName("DANE"))
        assertEquals(BootstrapMethod.NOISE, BootstrapMethod.fromName("noise"))
        assertEquals(null, BootstrapMethod.fromName("unknown"))
    }
}
