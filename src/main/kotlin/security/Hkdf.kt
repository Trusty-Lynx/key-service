package de.trustylynx.security

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// HKDF-SHA256 (RFC 5869) from the handbook: salt is 32 zero bytes, output is 32 bytes, info is the label as UTF-8
fun hkdf(ikm: ByteArray, label: String): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))   // extract: the salt is the key
    val prk = mac.doFinal(ikm)
    try {
        mac.init(SecretKeySpec(prk, "HmacSHA256"))   // expand: the prk is the key
        mac.update(label.toByteArray(Charsets.UTF_8))
        mac.update(1.toByte())
        return mac.doFinal()   // 32 bytes is exactly one block, so we never need a second one
    } finally {
        prk.fill(0)
    }
}
