package com.automatethethings.truststrap.config

import java.net.URI

data class TrustStrapConfig(
    val daneEnabled: Boolean = false,
    val noiseEnabled: Boolean = false,
    val spkiEnabled: Boolean = false,
    val directEnabled: Boolean = false,
    val daneConfig: DANEConfig = DANEConfig(),
    val noiseConfig: NoiseConfig = NoiseConfig(),
    val spkiConfig: SPKIConfig = SPKIConfig(),
    val directConfig: DirectConfig = DirectConfig(),
    val timeoutSeconds: Int = 15,
    val methodOrder: List<BootstrapMethod> = BootstrapMethod.DEFAULT_ORDER
) {
    fun getEnabledMethods(): List<BootstrapMethod> {
        return methodOrder.filter { method ->
            when (method) {
                BootstrapMethod.DANE -> daneEnabled
                BootstrapMethod.NOISE -> noiseEnabled
                BootstrapMethod.SPKI -> spkiEnabled
                BootstrapMethod.DIRECT -> directEnabled
            }
        }
    }

    fun hasConfiguredMethod(): Boolean = getEnabledMethods().any { method ->
        when (method) {
            BootstrapMethod.DANE -> daneConfig.serverUrl.isNotBlank()
            BootstrapMethod.NOISE -> noiseConfig.serverAddress.isNotBlank() && noiseConfig.serverStaticKey.isNotBlank()
            BootstrapMethod.SPKI -> spkiConfig.serverUrl.isNotBlank() && spkiConfig.spkiPinSha256.isNotBlank()
            BootstrapMethod.DIRECT -> directConfig.serverUrl.isNotBlank()
        }
    }

    fun deriveFromUrl(url: String): TrustStrapConfig {
        if (url.isBlank()) return this
        val parsed = try { URI.create(url) } catch (e: IllegalArgumentException) { return this }
        val host = parsed.host ?: return this
        val port = if (parsed.port > 0) parsed.port else 8443
        val baseUrl = "https://$host:$port"
        val noiseAddr = "$host:${port + 2}"
        return copy(
            daneConfig = daneConfig.copy(serverUrl = baseUrl),
            noiseConfig = noiseConfig.copy(serverAddress = noiseAddr),
            spkiConfig = spkiConfig.copy(serverUrl = baseUrl),
            directConfig = directConfig.copy(serverUrl = baseUrl)
        )
    }
}
