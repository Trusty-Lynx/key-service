package de.trustylynx.pepperhmac

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// NUR ZUM TESTEN – kommt später aus dem Docker Secret, nie echte Werte ins Repo
val TEST_PEPPER_LOGIN = "7a117269da84a2b92f7a6e818a5fbd5960ab53e59d6516b8be8580bf34536b92".hexToByteArray()
val TEST_PEPPER_VAULT = ByteArray(32) // Platzhalter, in der Doku gibt es keinen Testwert

fun pepperHmac(pepper: ByteArray, key: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")          // HMAC-Algorithmus holen
    mac.init(SecretKeySpec(pepper, "HmacSHA256"))    // pepper als Schlüssel setzen
    return mac.doFinal(key)                          // key hineingeben → 32 Byte Ergebnis
}