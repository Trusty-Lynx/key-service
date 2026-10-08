package de.trustylynx.domain

import de.trustylynx.persistence.ServerKeyRepository
import de.trustylynx.secureUserKey.wrapKey
import java.security.SecureRandom

class ServerKeyService(
    private val keys: ServerKeyRepository,
    private val msk: ByteArray,
) {

    /** Würfelt SDK_u, packt ihn mit dem MSK ein und speichert ihn als Version 1. */
    suspend fun createForNewUser(userId: String): Int {
        val sdkU = ByteArray(SDK_LENGTH).also { SecureRandom().nextBytes(it) }
        try {
            val wrapped = wrapKey(msk, sdkU, aad(userId, FIRST_VERSION))   // 60 Byte
            keys.create(userId, FIRST_VERSION, wrapped)
            return FIRST_VERSION
        } finally {
            sdkU.fill(0)   // SDK_u überschreiben, auch wenn create() eine Exception wirft
        }
    }

    companion object {
        const val FIRST_VERSION = 1
        private const val SDK_LENGTH = 32

        /** Muss beim Auspacken (derive) exakt gleich gebaut werden. */
        fun aad(userId: String, version: Int): ByteArray =
            "TL-KEY|$userId|v$version".toByteArray(Charsets.UTF_8)
    }
}


