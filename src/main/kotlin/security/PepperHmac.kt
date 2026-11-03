package de.trustylynx.security

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun pepperHmac(pepper: ByteArray, key: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(pepper, "HmacSHA256"))
    return mac.doFinal(key)
}
