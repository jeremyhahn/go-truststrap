package com.automatethethings.truststrap.error

import com.automatethethings.truststrap.config.BootstrapMethod

sealed class TrustStrapException(message: String, cause: Throwable? = null) : Exception(message, cause)

class DANEException(val reason: String, cause: Throwable? = null) :
    TrustStrapException("DANE bootstrap failed: $reason", cause)

class NoiseBootstrapException(val reason: String, cause: Throwable? = null) :
    TrustStrapException("Noise bootstrap failed: $reason", cause)

class SPKIException(val expectedPin: String, val actualPin: String? = null) :
    TrustStrapException(
        if (actualPin != null) "SPKI pin mismatch: expected $expectedPin, got $actualPin"
        else "SPKI verification failed: expected pin $expectedPin"
    )

class DirectException(val reason: String, val httpStatusCode: Int? = null, cause: Throwable? = null) :
    TrustStrapException(
        if (httpStatusCode != null) "Direct bootstrap failed (HTTP $httpStatusCode): $reason"
        else "Direct bootstrap failed: $reason",
        cause
    )

class BootstrapFailedException(val attempts: List<MethodAttemptError>) :
    TrustStrapException(buildMessage(attempts)) {
    companion object {
        private fun buildMessage(attempts: List<MethodAttemptError>): String {
            if (attempts.isEmpty()) return "Bootstrap failed: no methods configured"
            val details = attempts.joinToString(", ") { "${it.method}: ${it.error.message}" }
            return "Bootstrap failed: all methods failed [$details]"
        }
    }
}

data class MethodAttemptError(val method: BootstrapMethod, val error: Throwable)

class ConfigException(val reason: String) :
    TrustStrapException("Invalid bootstrap configuration: $reason")

class NoMethodsConfiguredException :
    TrustStrapException("No bootstrap methods configured: enable at least one of DANE, Noise, SPKI, or Direct")

class CertificateParseException(val reason: String, cause: Throwable? = null) :
    TrustStrapException("Certificate parsing failed: $reason", cause)
