package de.trustylynx.security

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.GCMParameterSpec

fun unwrapKey(msk: ByteArray, wrapped: ByteArray, aad: ByteArray): ByteArray {
    // Falsche Länge = kaputte Daten, genauso behandeln wie einen falschen Tag
    if (wrapped.size != 60) throw AEADBadTagException("wrapped_sdk must be 60 bytes")
    val nonce = wrapped.copyOfRange(0, 12)
    val ciphertext = wrapped.copyOfRange(12, wrapped.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(msk, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD(aad)
    return cipher.doFinal(ciphertext)   // wirft AEADBadTagException, wenn MSK/AAD falsch oder Daten manipuliert
}


