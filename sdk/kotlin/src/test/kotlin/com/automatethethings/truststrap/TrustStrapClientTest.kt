package com.automatethethings.truststrap

import com.automatethethings.truststrap.config.*
import com.automatethethings.truststrap.error.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TrustStrapClientTest {

    @Test
    fun `fetchCABundle throws NoMethodsConfiguredException when no methods enabled`() {
        val config = TrustStrapConfig()
        val client = TrustStrapClient(config)

        assertThrows<NoMethodsConfiguredException> {
            client.fetchCABundle()
        }
    }

    @Test
    fun `fetchWithMethod DANE throws when server URL blank`() {
        val config = TrustStrapConfig(
            daneEnabled = true,
            daneConfig = DANEConfig(serverUrl = "")
        )
        val client = TrustStrapClient(config)

        assertThrows<DANEException> {
            client.fetchWithMethod(BootstrapMethod.DANE)
        }
    }

    @Test
    fun `fetchWithMethod NOISE throws when server address blank`() {
        val config = TrustStrapConfig(
            noiseEnabled = true,
            noiseConfig = NoiseConfig(serverAddress = "", serverStaticKey = "aa".repeat(32))
        )
        val client = TrustStrapClient(config)

        assertThrows<NoiseBootstrapException> {
            client.fetchWithMethod(BootstrapMethod.NOISE)
        }
    }

    @Test
    fun `fetchWithMethod NOISE throws when server static key blank`() {
        val config = TrustStrapConfig(
            noiseEnabled = true,
            noiseConfig = NoiseConfig(serverAddress = "localhost:8445", serverStaticKey = "")
        )
        val client = TrustStrapClient(config)

        assertThrows<NoiseBootstrapException> {
            client.fetchWithMethod(BootstrapMethod.NOISE)
        }
    }

    @Test
    fun `fetchWithMethod NOISE throws when server static key wrong length`() {
        val config = TrustStrapConfig(
            noiseEnabled = true,
            noiseConfig = NoiseConfig(serverAddress = "localhost:8445", serverStaticKey = "aabb")
        )
        val client = TrustStrapClient(config)

        assertThrows<NoiseBootstrapException> {
            client.fetchWithMethod(BootstrapMethod.NOISE)
        }
    }

    @Test
    fun `fetchWithMethod NOISE throws on invalid address format`() {
        val config = TrustStrapConfig(
            noiseEnabled = true,
            noiseConfig = NoiseConfig(
                serverAddress = "invalid-no-port",
                serverStaticKey = "aa".repeat(32)
            )
        )
        val client = TrustStrapClient(config)

        assertThrows<NoiseBootstrapException> {
            client.fetchWithMethod(BootstrapMethod.NOISE)
        }
    }

    @Test
    fun `fetchWithMethod SPKI throws when server URL blank`() {
        val config = TrustStrapConfig(
            spkiEnabled = true,
            spkiConfig = SPKIConfig(serverUrl = "", spkiPinSha256 = "aa".repeat(32))
        )
        val client = TrustStrapClient(config)

        assertThrows<SPKIException> {
            client.fetchWithMethod(BootstrapMethod.SPKI)
        }
    }

    @Test
    fun `fetchWithMethod SPKI throws when pin blank`() {
        val config = TrustStrapConfig(
            spkiEnabled = true,
            spkiConfig = SPKIConfig(serverUrl = "https://example.com", spkiPinSha256 = "")
        )
        val client = TrustStrapClient(config)

        assertThrows<SPKIException> {
            client.fetchWithMethod(BootstrapMethod.SPKI)
        }
    }

    @Test
    fun `fetchWithMethod SPKI throws when pin wrong length`() {
        val config = TrustStrapConfig(
            spkiEnabled = true,
            spkiConfig = SPKIConfig(serverUrl = "https://example.com", spkiPinSha256 = "aabb")
        )
        val client = TrustStrapClient(config)

        assertThrows<ConfigException> {
            client.fetchWithMethod(BootstrapMethod.SPKI)
        }
    }

    @Test
    fun `fetchWithMethod DIRECT throws when server URL blank`() {
        val config = TrustStrapConfig(
            directEnabled = true,
            directConfig = DirectConfig(serverUrl = "")
        )
        val client = TrustStrapClient(config)

        assertThrows<DirectException> {
            client.fetchWithMethod(BootstrapMethod.DIRECT)
        }
    }

    @Test
    fun `fetchCABundle tries all enabled methods and throws BootstrapFailedException`() {
        val config = TrustStrapConfig(
            daneEnabled = true,
            directEnabled = true,
            daneConfig = DANEConfig(serverUrl = "https://nonexistent.invalid:9999"),
            directConfig = DirectConfig(serverUrl = "https://nonexistent.invalid:9999"),
            timeoutSeconds = 2
        )
        val client = TrustStrapClient(config)

        val ex = assertThrows<BootstrapFailedException> {
            client.fetchCABundle()
        }
        assertEquals(2, ex.attempts.size)
        assertEquals(BootstrapMethod.DANE, ex.attempts[0].method)
        assertEquals(BootstrapMethod.DIRECT, ex.attempts[1].method)
    }

    @Test
    fun `fetchWithMethod NOISE throws on unreachable host`() {
        val config = TrustStrapConfig(
            noiseEnabled = true,
            noiseConfig = NoiseConfig(
                serverAddress = "192.0.2.1:1",  // TEST-NET, guaranteed unreachable
                serverStaticKey = "aa".repeat(32)
            ),
            timeoutSeconds = 2
        )
        val client = TrustStrapClient(config)

        assertThrows<NoiseBootstrapException> {
            client.fetchWithMethod(BootstrapMethod.NOISE)
        }
    }

    @Test
    fun `constructor accepts config and does not throw`() {
        val config = TrustStrapConfig(timeoutSeconds = 5)
        @Suppress("UNUSED_VARIABLE")
        val client = TrustStrapClient(config)
        // Just verifying construction succeeds
        assertTrue(true)
    }
}
