/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package com.automatethethings.truststrap

import com.automatethethings.truststrap.error.NoiseBootstrapException
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Noise_NK session for initiator (client) side.
 *
 * Implements the NK handshake pattern where the initiator knows
 * the responder's static public key beforehand:
 *   -> e, es (initiator sends ephemeral, DH with server static)
 *   <- e, ee (responder sends ephemeral, performs DH)
 *
 * After the handshake completes, [encrypt] and [decrypt] provide
 * authenticated encryption for transport messages.
 *
 * @property serverStaticKey The 32-byte X25519 public key of the server.
 */
class NoiseNKSession(private val serverStaticKey: ByteArray) {

    companion object {
        private const val PROTOCOL_NAME = "Noise_NK_25519_ChaChaPoly_SHA256"
        internal const val KEY_SIZE = 32
    }

    private val secureRandom = SecureRandom()

    // Ephemeral keypair
    private var ephemeralPrivateKey = ByteArray(KEY_SIZE)
    private var ephemeralPublicKey = ByteArray(KEY_SIZE)

    // Symmetric state
    private var chainingKey = ByteArray(KEY_SIZE)
    private var handshakeHash = ByteArray(KEY_SIZE)
    private var encryptionKey: ByteArray? = null
    private var handshakeNonce: Long = 0

    // Transport keys
    private var sendKey: ByteArray? = null
    private var recvKey: ByteArray? = null
    private var sendNonce: Long = 0
    private var recvNonce: Long = 0

    init {
        initializeSymmetricState()
        generateEphemeralKey()
    }

    /**
     * Create first handshake message: -> e, es
     */
    fun createHandshakeMessage1(): ByteArray {
        mixHash(ephemeralPublicKey)
        val esSecret = x25519(ephemeralPrivateKey, serverStaticKey)
        mixKey(esSecret)
        return ephemeralPublicKey.copyOf()
    }

    /**
     * Process second handshake message: <- e, ee
     */
    fun processHandshakeMessage2(message: ByteArray) {
        if (message.size < KEY_SIZE) {
            throw NoiseBootstrapException("Message too short: ${message.size}")
        }
        val serverEphemeralKey = message.copyOfRange(0, KEY_SIZE)
        mixHash(serverEphemeralKey)

        val eeSecret = x25519(ephemeralPrivateKey, serverEphemeralKey)
        mixKey(eeSecret)

        if (message.size > KEY_SIZE) {
            val encryptedPayload = message.copyOfRange(KEY_SIZE, message.size)
            decryptAndHash(encryptedPayload)
        }

        splitSymmetricState()
    }

    /**
     * Encrypt a transport message after handshake is complete.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val key = sendKey ?: throw NoiseBootstrapException("Session not established")
        val nonce = createNonce(sendNonce++)
        return chacha20Poly1305Encrypt(key, nonce, plaintext, ByteArray(0))
    }

    /**
     * Decrypt a transport message after handshake is complete.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        val key = recvKey ?: throw NoiseBootstrapException("Session not established")
        val nonce = createNonce(recvNonce++)
        return chacha20Poly1305Decrypt(key, nonce, ciphertext, ByteArray(0))
    }

    // -------------------------------------------------------------------------
    // Symmetric state operations
    // -------------------------------------------------------------------------

    private fun initializeSymmetricState() {
        val protocolBytes = PROTOCOL_NAME.toByteArray()
        if (protocolBytes.size <= KEY_SIZE) {
            handshakeHash = ByteArray(KEY_SIZE)
            System.arraycopy(protocolBytes, 0, handshakeHash, 0, protocolBytes.size)
        } else {
            handshakeHash = sha256(protocolBytes)
        }
        chainingKey = handshakeHash.copyOf()
        mixHash(ByteArray(0))          // MixHash(prologue)
        mixHash(serverStaticKey)       // MixHash(rs) — NK pre-message
        encryptionKey = ByteArray(KEY_SIZE)
        handshakeNonce = 0
    }

    private fun generateEphemeralKey() {
        ephemeralPrivateKey = ByteArray(KEY_SIZE).also { secureRandom.nextBytes(it) }
        ephemeralPrivateKey[0] = (ephemeralPrivateKey[0].toInt() and 248).toByte()
        ephemeralPrivateKey[31] = (ephemeralPrivateKey[31].toInt() and 127).toByte()
        ephemeralPrivateKey[31] = (ephemeralPrivateKey[31].toInt() or 64).toByte()
        ephemeralPublicKey = x25519ScalarMultBase(ephemeralPrivateKey)
    }

    private fun mixHash(data: ByteArray) {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(handshakeHash)
        digest.update(data)
        handshakeHash = digest.digest()
    }

    private fun mixKey(inputKeyMaterial: ByteArray) {
        val (ck, k) = hkdf2(chainingKey, inputKeyMaterial)
        chainingKey = ck
        encryptionKey = k
        handshakeNonce = 0
    }

    private fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val nonce = createNonce(handshakeNonce)
        val key = encryptionKey ?: throw NoiseBootstrapException("No encryption key")
        val plaintext = chacha20Poly1305Decrypt(key, nonce, ciphertext, handshakeHash)
        mixHash(ciphertext)
        handshakeNonce++
        return plaintext
    }

    private fun splitSymmetricState() {
        val (k1, k2) = hkdf2(chainingKey, ByteArray(0))
        sendKey = k1
        recvKey = k2
        sendNonce = 0
        recvNonce = 0
    }

    // -------------------------------------------------------------------------
    // Crypto primitives
    // -------------------------------------------------------------------------

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun hkdf2(salt: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(byteArrayOf(0x01))
        val t1 = mac.doFinal()

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(t1)
        mac.update(byteArrayOf(0x02))
        val t2 = mac.doFinal()

        return Pair(t1, t2)
    }

    private fun createNonce(n: Long): ByteArray =
        ByteBuffer.allocate(12)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0)
            .putLong(n)
            .array()

    // -------------------------------------------------------------------------
    // X25519 key agreement
    // -------------------------------------------------------------------------

    private fun x25519ScalarMultBase(scalar: ByteArray): ByteArray {
        val basePoint = ByteArray(32)
        basePoint[0] = 9
        return x25519ScalarMultPure(scalar, basePoint)
    }

    internal fun x25519(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        return try {
            val privKeySpec = PKCS8EncodedKeySpec(wrapX25519PrivateKey(privateKey))
            val pubKeySpec = X509EncodedKeySpec(wrapX25519PublicKey(publicKey))

            val keyFactory = KeyFactory.getInstance("X25519")
            val privKey = keyFactory.generatePrivate(privKeySpec)
            val pubKey = keyFactory.generatePublic(pubKeySpec)

            val keyAgreement = KeyAgreement.getInstance("X25519")
            keyAgreement.init(privKey)
            keyAgreement.doPhase(pubKey, true)
            keyAgreement.generateSecret()
        } catch (e: Exception) {
            x25519ScalarMultPure(privateKey, publicKey)
        }
    }

    private fun x25519ScalarMultPure(k: ByteArray, u: ByteArray): ByteArray {
        val p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

        val kClamped = k.copyOf()
        kClamped[0] = (kClamped[0].toInt() and 248).toByte()
        kClamped[31] = (kClamped[31].toInt() and 127).toByte()
        kClamped[31] = (kClamped[31].toInt() or 64).toByte()

        val uInt = decodeLittleEndian(u).mod(p)

        val x1 = uInt
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = uInt
        var z3 = BigInteger.ONE

        var swap = BigInteger.ZERO

        for (t in 254 downTo 0) {
            val kT = kClamped[t / 8].toInt().ushr(t % 8).and(1)
            val kTBig = BigInteger.valueOf(kT.toLong())

            swap = swap.xor(kTBig)
            val (cx2, cx3) = cswap(swap, x2, x3)
            val (cz2, cz3) = cswap(swap, z2, z3)
            x2 = cx2; x3 = cx3; z2 = cz2; z3 = cz3
            swap = kTBig

            val a = x2.add(z2).mod(p)
            val aa = a.multiply(a).mod(p)
            val b = x2.subtract(z2).mod(p)
            val bb = b.multiply(b).mod(p)
            val e = aa.subtract(bb).mod(p)
            val c = x3.add(z3).mod(p)
            val d = x3.subtract(z3).mod(p)
            val da = d.multiply(a).mod(p)
            val cb = c.multiply(b).mod(p)
            x3 = da.add(cb).mod(p).pow(2).mod(p)
            z3 = x1.multiply(da.subtract(cb).mod(p).pow(2)).mod(p)
            x2 = aa.multiply(bb).mod(p)
            val a24 = BigInteger.valueOf(121665)
            z2 = e.multiply(aa.add(a24.multiply(e))).mod(p)
        }

        val (fx2, _) = cswap(swap, x2, x3)
        val (fz2, _) = cswap(swap, z2, z3)

        val result = fx2.multiply(fz2.modPow(p.subtract(BigInteger.valueOf(2)), p)).mod(p)
        return encodeLittleEndian(result)
    }

    private fun decodeLittleEndian(b: ByteArray): BigInteger =
        BigInteger(1, b.reversedArray())

    private fun encodeLittleEndian(n: BigInteger): ByteArray {
        var bytes = n.toByteArray()
        if (bytes.size > 32 && bytes[0] == 0.toByte()) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }
        val result = ByteArray(32)
        val offset = 32 - bytes.size
        System.arraycopy(bytes, 0, result, offset, bytes.size)
        return result.reversedArray()
    }

    private fun cswap(swap: BigInteger, a: BigInteger, b: BigInteger): Pair<BigInteger, BigInteger> =
        if (swap == BigInteger.ONE) Pair(b, a) else Pair(a, b)

    private fun wrapX25519PrivateKey(raw: ByteArray): ByteArray {
        val header = byteArrayOf(
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
            0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
        )
        return header + raw
    }

    private fun wrapX25519PublicKey(raw: ByteArray): ByteArray {
        val header = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05,
            0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
        )
        return header + raw
    }

    // -------------------------------------------------------------------------
    // ChaCha20-Poly1305 AEAD
    // -------------------------------------------------------------------------

    private fun chacha20Poly1305Encrypt(
        key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray
    ): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun chacha20Poly1305Decrypt(
        key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray
    ): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }
}
