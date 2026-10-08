package de.trustylynx.security

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec


fun pepperHmac(pepper: ByteArray, key: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")          // HMAC-Algorithmus holen
    mac.init(SecretKeySpec(pepper, "HmacSHA256"))    // pepper als Schlüssel setzen
    return mac.doFinal(key)                          // key hineingeben → 32 Byte Ergebnis
}