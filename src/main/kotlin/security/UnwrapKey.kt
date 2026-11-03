package de.trustylynx.security

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

fun unwrapKey(msk: ByteArray, wrapped: ByteArray, aad: ByteArray): ByteArray {
    // a wrong length means broken data, so treat it like a wrong tag
    if (wrapped.size != 60) throw AEADBadTagException("wrapped_sdk must be 60 bytes")
    val nonce = wrapped.copyOfRange(0, 12)
    val ciphertext = wrapped.copyOfRange(12, wrapped.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(msk, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD(aad)
    // throws AEADBadTagException if the msk or aad is wrong or the data was changed
    return cipher.doFinal(ciphertext)
}
