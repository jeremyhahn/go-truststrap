package com.automatethethings.truststrap.config

enum class BootstrapMethod(val displayName: String, val description: String) {
    DANE("DANE (DNS-based)", "Uses TLSA DNS records with DNSSEC validation for strongest verification"),
    NOISE("Noise Protocol", "Encrypted channel using pre-shared Curve25519 server key"),
    SPKI("SPKI Pinning", "TLS with certificate public key pin verification"),
    DIRECT("Direct HTTPS", "Standard HTTPS using system trust store (fallback)");

    companion object {
        val DEFAULT_ORDER = listOf(DANE, NOISE, SPKI, DIRECT)
        fun fromName(name: String): BootstrapMethod? = entries.find { it.name.equals(name, ignoreCase = true) }
    }
}
