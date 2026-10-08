package de.trustylynx.security

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.GCMParameterSpec

fun wrapKey(msk: ByteArray, sdkU: ByteArray, aad: ByteArray): ByteArray {
    val nonce = ByteArray(12).also{ SecureRandom().nextBytes(it)}
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(msk, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD(aad)
    val ciphertext = cipher.doFinal(sdkU)   // 32 Byte Key + 16 Byte Tag = 48 Byte
    return nonce + ciphertext
}