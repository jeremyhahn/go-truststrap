package com.automatethethings.truststrap.result

import com.automatethethings.truststrap.config.BootstrapMethod

data class CABundleResult(
    val bundlePEM: ByteArray,
    val certificates: List<ByteArray>,
    val method: BootstrapMethod,
    val fetchedAt: Long = System.currentTimeMillis()
) {
    val certificateCount: Int get() = certificates.size
    val isNotEmpty: Boolean get() = certificates.isNotEmpty()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CABundleResult) return false
        if (!bundlePEM.contentEquals(other.bundlePEM)) return false
        if (certificates.size != other.certificates.size) return false
        for (i in certificates.indices) {
            if (!certificates[i].contentEquals(other.certificates[i])) return false
        }
        if (method != other.method) return false
        if (fetchedAt != other.fetchedAt) return false
        return true
    }

    override fun hashCode(): Int {
        var result = bundlePEM.contentHashCode()
        result = 31 * result + certificates.fold(0) { acc, cert -> 31 * acc + cert.contentHashCode() }
        result = 31 * result + method.hashCode()
        result = 31 * result + fetchedAt.hashCode()
        return result
    }

    override fun toString(): String {
        return "CABundleResult(method=$method, certificates=${certificates.size}, bundleSize=${bundlePEM.size}, fetchedAt=$fetchedAt)"
    }
}
