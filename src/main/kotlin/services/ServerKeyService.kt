package de.trustylynx.services

import de.trustylynx.models.GetKeyResponse
import de.trustylynx.models.IntegrityError
import de.trustylynx.models.NewUserResponse
import de.trustylynx.models.NotFound
import de.trustylynx.repositories.ServerKeyRepository
import de.trustylynx.security.hkdf
import de.trustylynx.security.unwrapKey
import de.trustylynx.security.wrapKey
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import kotlin.io.encoding.Base64

private const val FIRST_VERSION = 1
private const val SDK_LENGTH = 32

private val audit = LoggerFactory.getLogger("audit")

class ServerKeyService(
    private val keys: ServerKeyRepository,
    private val msk: ByteArray,
) {
    suspend fun createForNewUser(userId: String): NewUserResponse {
        val sdkU = ByteArray(SDK_LENGTH)
        SecureRandom().nextBytes(sdkU)
        try {
            val wrapped = wrapKey(msk, sdkU, aad(userId, FIRST_VERSION))
            keys.create(userId, FIRST_VERSION, wrapped)
            return NewUserResponse(FIRST_VERSION.toString())
        } finally {
            // wipe it even when create() throws
            sdkU.fill(0)
        }
    }

    suspend fun derive(userId: String, version: Int?, alg: String): GetKeyResponse {
        val stored = keys.find(userId, version) ?: throw NotFound()
        val sdkU = try {
            unwrapKey(msk, stored.wrappedSdk, aad(userId, stored.version))
        } catch (_: AEADBadTagException) {
            // someone changed wrapped_sdk in the db, or the msk is wrong
            audit.error("integrity_error: wrapped_sdk für userId={} v{} lässt sich nicht entpacken", userId, stored.version)
            throw IntegrityError()
        }
        val key = try {
            hkdf(sdkU, "TL-L2-$alg")
        } finally {
            sdkU.fill(0)
        }
        try {
            return GetKeyResponse(Base64.encode(key), stored.version)
        } finally {
            key.fill(0)
        }
    }

    companion object {
        // don't change this string, stored keys can only be unwrapped with the exact same bytes
        fun aad(userId: String, version: Int): ByteArray =
            "TL-KEY|$userId|v$version".toByteArray(Charsets.UTF_8)
    }
}
