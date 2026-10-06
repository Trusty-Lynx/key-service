package de.trustylynx.newUser

import kotlinx.serialization.Serializable

@Serializable
data class ServerKey(
    val userId: String,
    val keyVersion: Int, // die "1" – wichtig für spätere Key-Rotation
    val wrappedSdk: String,   // Base64, weil JSON keine ByteArrays kann
    val active: Boolean
)
