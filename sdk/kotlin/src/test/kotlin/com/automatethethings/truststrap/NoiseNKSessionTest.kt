package com.automatethethings.truststrap

import com.automatethethings.truststrap.error.NoiseBootstrapException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NoiseNKSessionTest {

    private val testServerKey = ByteArray(32) { (it + 1).toByte() }

    @Test
    fun `createHandshakeMessage1 returns 32-byte ephemeral key`() {
        val session = NoiseNKSession(testServerKey)
        val msg1 = session.createHandshakeMessage1()
        assertEquals(32, msg1.size)
    }

    @Test
    fun `createHandshakeMessage1 returns different keys each time`() {
        val session1 = NoiseNKSession(testServerKey)
        val session2 = NoiseNKSession(testServerKey)
        val msg1 = session1.createHandshakeMessage1()
        val msg2 = session2.createHandshakeMessage1()
        // Ephemeral keys are random, extremely unlikely to match
        assertTrue(!msg1.contentEquals(msg2))
    }

    @Test
    fun `processHandshakeMessage2 rejects short message`() {
        val session = NoiseNKSession(testServerKey)
        session.createHandshakeMessage1()
        assertThrows<NoiseBootstrapException> {
            session.processHandshakeMessage2(ByteArray(16))
        }
    }

    @Test
    fun `encrypt throws before handshake completes`() {
        val session = NoiseNKSession(testServerKey)
        session.createHandshakeMessage1()
        // Handshake not completed (no processHandshakeMessage2 called)
        assertThrows<NoiseBootstrapException> {
            session.encrypt("test".toByteArray())
        }
    }

    @Test
    fun `decrypt throws before handshake completes`() {
        val session = NoiseNKSession(testServerKey)
        session.createHandshakeMessage1()
        assertThrows<NoiseBootstrapException> {
            session.decrypt(ByteArray(48))
        }
    }

    @Test
    fun `x25519 scalar mult base produces 32-byte output`() {
        val session = NoiseNKSession(testServerKey)
        // Use reflection to call the internal x25519 method
        val privateKey = ByteArray(32) { 0x42.toByte() }.also {
            it[0] = (it[0].toInt() and 248).toByte()
            it[31] = (it[31].toInt() and 127).toByte()
            it[31] = (it[31].toInt() or 64).toByte()
        }
        val publicKey = ByteArray(32).also { it[0] = 9 }
        val result = session.x25519(privateKey, publicKey)
        assertNotNull(result)
        assertEquals(32, result.size)
    }

    @Test
    fun `x25519 is deterministic`() {
        val session = NoiseNKSession(testServerKey)
        val privateKey = ByteArray(32) { 0x42.toByte() }.also {
            it[0] = (it[0].toInt() and 248).toByte()
            it[31] = (it[31].toInt() and 127).toByte()
            it[31] = (it[31].toInt() or 64).toByte()
        }
        val publicKey = ByteArray(32).also { it[0] = 9 }
        val result1 = session.x25519(privateKey, publicKey)
        val result2 = session.x25519(privateKey, publicKey)
        assertTrue(result1.contentEquals(result2))
    }
}
