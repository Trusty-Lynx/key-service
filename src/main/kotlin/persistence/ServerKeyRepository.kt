package de.trustylynx.persistence

interface ServerKeyRepository {
    /** Wirft [de.trustylynx.common.AlreadyExists], wenn es (userId, version) schon gibt. */
    suspend fun create(userId: String, version: Int, wrappedSdk: ByteArray)
}
