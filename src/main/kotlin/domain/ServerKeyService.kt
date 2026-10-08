package de.trustylynx.domain

import de.trustylynx.common.IntegrityError
import de.trustylynx.common.NotFound
import de.trustylynx.persistence.ServerKeyRepository
import de.trustylynx.security.hkdf
import de.trustylynx.security.unwrapKey
import de.trustylynx.security.wrapKey
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import javax.crypto.AEADBadTagException

/** Teilschlüssel (32 Byte) + die Version, aus der er stammt. */
class DerivedKey(val key: ByteArray, val version: Int)

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

    /** Packt SDK_u aus und leitet den Teilschlüssel für [alg] ab ("aes" / "chacha"). */
    suspend fun derive(userId: String, version: Int?, alg: String): DerivedKey {
        val stored = keys.find(userId, version) ?: throw NotFound()
        val sdkU = try {
            unwrapKey(msk, stored.wrappedSdk, aad(userId, stored.version))
        } catch (e: AEADBadTagException) {
            // Audit-Eintrag: jemand hat wrapped_sdk in der DB verändert (oder falscher MSK)
            audit.error("integrity_error: wrapped_sdk für userId={} v{} lässt sich nicht entpacken", userId, stored.version)
            throw IntegrityError()
        }
        try {
            return DerivedKey(hkdf(sdkU, "TL-L2-$alg"), stored.version)
        } finally {
            sdkU.fill(0)   // SDK_u sofort überschreiben
        }
    }

    companion object {
        const val FIRST_VERSION = 1
        private val audit = LoggerFactory.getLogger("audit")
        private const val SDK_LENGTH = 32

        /** Muss beim Auspacken (derive) exakt gleich gebaut werden. */
        fun aad(userId: String, version: Int): ByteArray =
            "TL-KEY|$userId|v$version".toByteArray(Charsets.UTF_8)
    }
}


