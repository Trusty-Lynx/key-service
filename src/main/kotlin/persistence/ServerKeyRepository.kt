package de.trustylynx.persistence

/** Eine Zeile aus server_keys: Version + eingepackter SDK_u (60 Byte). */
class WrappedKey(val version: Int, val wrappedSdk: ByteArray)

interface ServerKeyRepository {
    /** Wirft [de.trustylynx.common.AlreadyExists], wenn es (userId, version) schon gibt. */
    suspend fun create(userId: String, version: Int, wrappedSdk: ByteArray)

    /** Ohne [version] die aktive, mit [version] genau diese. null, wenn es keine gibt. */
    suspend fun find(userId: String, version: Int?): WrappedKey?
}
