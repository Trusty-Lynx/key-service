package de.trustylynx.security

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// HKDF-SHA256 (RFC 5869) wie im Handbuch: Salt = 32 × 00, Länge 32 B, info = Etikett als UTF-8
fun hkdf(ikm: ByteArray, label: String): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))   // Extract: Salt als Schlüssel
    val prk = mac.doFinal(ikm)
    try {
        mac.init(SecretKeySpec(prk, "HmacSHA256"))          // Expand: PRK als Schlüssel
        mac.update(label.toByteArray(Charsets.UTF_8))
        mac.update(1.toByte())
        return mac.doFinal()   // 32 Byte = genau ein Block, mehr Blöcke braucht man nicht
    } finally {
        prk.fill(0)
    }
}
