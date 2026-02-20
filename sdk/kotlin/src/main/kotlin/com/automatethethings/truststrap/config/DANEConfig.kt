package com.automatethethings.truststrap.config

data class DANEConfig(
    val serverUrl: String = "",
    val dnsServer: String = "8.8.8.8:53",
    val dnsOverTls: Boolean = false,
    val requireDnssec: Boolean = true
)
