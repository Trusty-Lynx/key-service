package de.trustylynx.security

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

fun wrapKey(msk: ByteArray, sdkU: ByteArray, aad: ByteArray): ByteArray {
    val nonce = ByteArray(12)
    SecureRandom().nextBytes(nonce)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(msk, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD(aad)
    val ciphertext = cipher.doFinal(sdkU)   // 32 byte key + 16 byte tag
    return nonce + ciphertext
}
