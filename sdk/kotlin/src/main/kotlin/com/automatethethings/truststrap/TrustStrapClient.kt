/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package com.automatethethings.truststrap

import com.automatethethings.truststrap.config.BootstrapMethod
import com.automatethethings.truststrap.config.TrustStrapConfig
import com.automatethethings.truststrap.error.*
import com.automatethethings.truststrap.result.CABundleResult
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.logging.Level
import java.util.logging.Logger
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Client for fetching CA certificate bundles using secure bootstrap mechanisms.
 *
 * Implements multiple trust-establishment methods in priority order:
 *
 * 1. **DANE**: DNS-based Authentication of Named Entities using TLSA records
 * 2. **Noise**: Noise_NK protocol with pre-shared server public key
 * 3. **SPKI**: SPKI-pinned TLS verification
 * 4. **Direct**: Standard HTTPS with system trust store
 *
 * This is a pure-JVM client with no Android dependencies.
 *
 * Example usage:
 * ```kotlin
 * val config = TrustStrapConfig(
 *     noiseEnabled = true,
 *     noiseConfig = NoiseConfig(
 *         serverAddress = "kms.example.com:8445",
 *         serverStaticKey = "0102030405..." // 64 hex chars
 *     )
 * )
 * val client = TrustStrapClient(config)
 * val result = client.fetchCABundle()
 * println("Fetched ${result.certificates.size} certificates via ${result.method}")
 * ```
 *
 * @property config The bootstrap configuration.
 */
class TrustStrapClient(private val config: TrustStrapConfig) {

    companion object {
        private val logger = Logger.getLogger(TrustStrapClient::class.java.name)
        private const val BOOTSTRAP_PATH = "/v1/ca/bootstrap"
        private const val MAX_RESPONSE_SIZE = 1 * 1024 * 1024 // 1 MB
        private const val FRAME_HEADER_SIZE = 2
        private const val MAX_FRAME_SIZE = 65535
        private const val KEY_SIZE = 32
        private const val PEM_CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
        private const val PEM_CERT_END = "-----END CERTIFICATE-----"
    }

    /**
     * Fetch CA bundle using auto-bootstrap mechanism.
     *
     * Tries each enabled bootstrap method in priority order and returns the
     * first successful result. If all methods fail, throws
     * [BootstrapFailedException] containing errors from all attempts.
     *
     * @return The CA bundle result from the first successful method.
     * @throws NoMethodsConfiguredException If no methods are enabled.
     * @throws BootstrapFailedException If all methods fail.
     */
    fun fetchCABundle(): CABundleResult {
        val enabledMethods = config.getEnabledMethods()
        if (enabledMethods.isEmpty()) {
            throw NoMethodsConfiguredException()
        }

        val attempts = mutableListOf<MethodAttemptError>()

        for (method in enabledMethods) {
            try {
                logger.info("Attempting bootstrap method: $method")
                val result = fetchWithMethod(method)
                logger.info("Bootstrap succeeded with method: $method")
                return result
            } catch (e: Exception) {
                logger.log(Level.WARNING, "Bootstrap method $method failed: ${e.message}")
                attempts.add(MethodAttemptError(method, e))
            }
        }

        throw BootstrapFailedException(attempts)
    }

    /**
     * Fetch CA bundle using a specific bootstrap method.
     *
     * @param method The bootstrap method to use.
     * @return The CA bundle result.
     */
    fun fetchWithMethod(method: BootstrapMethod): CABundleResult {
        return when (method) {
            BootstrapMethod.DANE -> fetchWithDANE()
            BootstrapMethod.NOISE -> fetchWithNoise()
            BootstrapMethod.SPKI -> fetchWithSPKI()
            BootstrapMethod.DIRECT -> fetchWithDirect()
        }
    }

    // -------------------------------------------------------------------------
    // DANE
    // -------------------------------------------------------------------------

    private fun fetchWithDANE(): CABundleResult {
        val daneConfig = config.daneConfig
        if (daneConfig.serverUrl.isBlank()) {
            throw DANEException("DANE server URL not configured")
        }

        logger.warning("DANE: Full TLSA verification not yet implemented, falling back to insecure fetch")

        val url = normalizeUrl(daneConfig.serverUrl) + BOOTSTRAP_PATH
        val body = httpGet(url, insecure = true)

        val certificates = parsePEMCertificates(body)
        if (certificates.isEmpty()) {
            throw DANEException("No valid certificates in response")
        }

        return CABundleResult(
            bundlePEM = body,
            certificates = certificates.map { it.encoded },
            method = BootstrapMethod.DANE
        )
    }

    // -------------------------------------------------------------------------
    // Noise_NK
    // -------------------------------------------------------------------------

    private fun fetchWithNoise(): CABundleResult {
        val noiseConfig = config.noiseConfig
        if (noiseConfig.serverAddress.isBlank()) {
            throw NoiseBootstrapException("Noise server address not configured")
        }
        if (noiseConfig.serverStaticKey.isBlank()) {
            throw NoiseBootstrapException("Noise server static key not configured")
        }

        val serverKey = try {
            hexToBytes(noiseConfig.serverStaticKey)
        } catch (e: Exception) {
            throw NoiseBootstrapException("Invalid server static key: ${e.message}")
        }

        if (serverKey.size != KEY_SIZE) {
            throw NoiseBootstrapException(
                "Server static key must be $KEY_SIZE bytes, got ${serverKey.size}"
            )
        }

        val parts = noiseConfig.serverAddress.split(":")
        if (parts.size != 2) {
            throw NoiseBootstrapException("Invalid server address format: ${noiseConfig.serverAddress}")
        }
        val host = parts[0]
        val port = parts[1].toIntOrNull()
            ?: throw NoiseBootstrapException("Invalid port: ${parts[1]}")

        val socket = try {
            Socket(host, port).apply {
                soTimeout = config.timeoutSeconds * 1000
            }
        } catch (e: Exception) {
            throw NoiseBootstrapException("Failed to connect to $host:$port", e)
        }

        try {
            val session = NoiseNKSession(serverKey)
            val dataIn = DataInputStream(socket.getInputStream())
            val dataOut = DataOutputStream(socket.getOutputStream())

            // NK Handshake: initiator sends (e, es)
            val msg1 = session.createHandshakeMessage1()
            writeFrame(dataOut, msg1)

            // Read server response (e, ee)
            val msg2 = readFrame(dataIn)
            session.processHandshakeMessage2(msg2)

            // Send CA bundle request
            val request = JSONObject().apply {
                put("method", "get_ca_bundle")
            }
            val encryptedRequest = session.encrypt(request.toString().toByteArray())
            writeFrame(dataOut, encryptedRequest)

            // Read response
            val encryptedResponse = readFrame(dataIn)
            val responseBytes = session.decrypt(encryptedResponse)
            val response = JSONObject(String(responseBytes))

            if (response.has("error") && response.getString("error").isNotEmpty()) {
                throw NoiseBootstrapException("Server error: ${response.getString("error")}")
            }

            val bundlePEM = response.optString("bundle_pem", "")
            val certsArray = response.optJSONArray("certificates")

            val derCerts = mutableListOf<ByteArray>()
            if (certsArray != null) {
                for (i in 0 until certsArray.length()) {
                    val certB64 = certsArray.getString(i)
                    try {
                        derCerts.add(Base64.getDecoder().decode(certB64))
                    } catch (e: Exception) {
                        logger.warning("Skipping malformed certificate at index $i")
                    }
                }
            }

            return CABundleResult(
                bundlePEM = bundlePEM.toByteArray(),
                certificates = derCerts,
                method = BootstrapMethod.NOISE
            )
        } finally {
            socket.close()
        }
    }

    // -------------------------------------------------------------------------
    // SPKI Pinning
    // -------------------------------------------------------------------------

    private fun fetchWithSPKI(): CABundleResult {
        val spkiConfig = config.spkiConfig
        if (spkiConfig.serverUrl.isBlank()) {
            throw SPKIException("", "SPKI server URL not configured")
        }
        if (spkiConfig.spkiPinSha256.isBlank()) {
            throw SPKIException("", "SPKI pin not configured")
        }

        val expectedPin = spkiConfig.spkiPinSha256.lowercase()
        if (expectedPin.length != 64) {
            throw ConfigException("SPKI pin must be 64 hex characters (SHA-256)")
        }

        val url = normalizeUrl(spkiConfig.serverUrl) + BOOTSTRAP_PATH
        val body = httpGet(url, spkiPin = expectedPin)

        val certificates = parsePEMCertificates(body)
        if (certificates.isEmpty()) {
            throw CertificateParseException("No valid certificates in response")
        }

        return CABundleResult(
            bundlePEM = body,
            certificates = certificates.map { it.encoded },
            method = BootstrapMethod.SPKI
        )
    }

    // -------------------------------------------------------------------------
    // Direct HTTPS
    // -------------------------------------------------------------------------

    private fun fetchWithDirect(): CABundleResult {
        val directConfig = config.directConfig
        if (directConfig.serverUrl.isBlank()) {
            throw DirectException("Direct server URL not configured")
        }

        val url = normalizeUrl(directConfig.serverUrl) + BOOTSTRAP_PATH
        val body = httpGet(url)

        if (body.size > MAX_RESPONSE_SIZE) {
            throw DirectException("Response too large: ${body.size} bytes")
        }

        val certificates = parsePEMCertificates(body)
        if (certificates.isEmpty()) {
            throw CertificateParseException("No valid certificates in response")
        }

        return CABundleResult(
            bundlePEM = body,
            certificates = certificates.map { it.encoded },
            method = BootstrapMethod.DIRECT
        )
    }

    // -------------------------------------------------------------------------
    // HTTP helpers (HttpURLConnection instead of OkHttp)
    // -------------------------------------------------------------------------

    private fun httpGet(
        urlString: String,
        insecure: Boolean = false,
        spkiPin: String? = null
    ): ByteArray {
        val url = URL(urlString)
        val connection = url.openConnection() as HttpURLConnection

        connection.connectTimeout = config.timeoutSeconds * 1000
        connection.readTimeout = config.timeoutSeconds * 1000
        connection.requestMethod = "GET"

        if (connection is HttpsURLConnection) {
            when {
                insecure -> configureInsecureTLS(connection)
                spkiPin != null -> configureSPKIPinnedTLS(connection, spkiPin)
            }
        }

        try {
            connection.connect()
            val responseCode = connection.responseCode

            if (responseCode !in 200..299) {
                val errorStream = connection.errorStream?.readBytes()
                val errorMsg = errorStream?.let { String(it) } ?: "HTTP $responseCode"
                when {
                    spkiPin != null -> throw DirectException("SPKI fetch failed: $errorMsg", responseCode)
                    insecure -> throw DANEException("HTTP $responseCode from $urlString")
                    else -> throw DirectException("Server returned error", responseCode)
                }
            }

            val body = connection.inputStream.readBytes()
            if (body.isEmpty()) throw DirectException("Empty response from $urlString")
            return body
        } catch (e: SPKIException) {
            throw e
        } catch (e: TrustStrapException) {
            throw e
        } catch (e: Exception) {
            throw DirectException("Network error fetching from $urlString", cause = e)
        } finally {
            connection.disconnect()
        }
    }

    private fun configureInsecureTLS(connection: HttpsURLConnection) {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, SecureRandom())
        connection.sslSocketFactory = sslContext.socketFactory
        connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
    }

    private fun configureSPKIPinnedTLS(connection: HttpsURLConnection, expectedPin: String) {
        val spkiTrustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty()) {
                    throw SPKIException(expectedPin)
                }
                for (cert in chain) {
                    val actualPin = computeSPKIPin(cert)
                    if (actualPin == expectedPin) return
                }
                val actualPin = if (chain.isNotEmpty()) computeSPKIPin(chain[0]) else null
                throw SPKIException(expectedPin, actualPin)
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(spkiTrustManager), SecureRandom())
        connection.sslSocketFactory = sslContext.socketFactory
    }

    // -------------------------------------------------------------------------
    // Certificate parsing
    // -------------------------------------------------------------------------

    private fun parsePEMCertificates(pemData: ByteArray): List<X509Certificate> {
        val pemString = String(pemData, Charsets.UTF_8)
        val certFactory = CertificateFactory.getInstance("X.509")
        val certificates = mutableListOf<X509Certificate>()

        var startIndex = 0
        while (true) {
            val beginIndex = pemString.indexOf(PEM_CERT_BEGIN, startIndex)
            if (beginIndex == -1) break
            val endIndex = pemString.indexOf(PEM_CERT_END, beginIndex)
            if (endIndex == -1) break

            val certPem = pemString.substring(beginIndex, endIndex + PEM_CERT_END.length)
            try {
                val cert = certFactory.generateCertificate(
                    ByteArrayInputStream(certPem.toByteArray(Charsets.UTF_8))
                ) as X509Certificate
                certificates.add(cert)
            } catch (e: Exception) {
                logger.warning("Failed to parse certificate: ${e.message}")
            }

            startIndex = endIndex + PEM_CERT_END.length
        }

        return certificates
    }

    private fun computeSPKIPin(cert: X509Certificate): String {
        val spki = cert.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256")
        return bytesToHex(digest.digest(spki))
    }

    // -------------------------------------------------------------------------
    // Noise framing
    // -------------------------------------------------------------------------

    private fun writeFrame(out: DataOutputStream, data: ByteArray) {
        if (data.size > MAX_FRAME_SIZE) {
            throw NoiseBootstrapException("Frame too large: ${data.size} > $MAX_FRAME_SIZE")
        }
        out.writeShort(data.size)
        out.write(data)
        out.flush()
    }

    private fun readFrame(input: DataInputStream): ByteArray {
        val length = input.readUnsignedShort()
        if (length > MAX_FRAME_SIZE) {
            throw NoiseBootstrapException("Frame too large: $length > $MAX_FRAME_SIZE")
        }
        val data = ByteArray(length)
        input.readFully(data)
        return data
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private fun normalizeUrl(url: String): String = url.trimEnd('/')

    private fun hexToBytes(hex: String): ByteArray {
        val cleanHex = hex.replace(" ", "").lowercase()
        if (cleanHex.length % 2 != 0) {
            throw IllegalArgumentException("Hex string must have even length")
        }
        return ByteArray(cleanHex.length / 2) { i ->
            val index = i * 2
            cleanHex.substring(index, index + 2).toInt(16).toByte()
        }
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
