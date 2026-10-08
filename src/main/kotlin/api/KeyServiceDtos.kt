package de.trustylynx.api

import kotlinx.serialization.Serializable   // für @Serializable an den DTOs

// ---- POST /internal/pepper-hmac ----

@Serializable //das was reinkommt
data class PepperHmacRequest(
    val purpose: String,
    val userId: String,
    val key: String
)

@Serializable //das was rausgeht
data class PepperHmacResponse(
    val h: String
)

// ---- POST /internal/users/create ----

@Serializable
data class NewUserRequest(
    val userId: String
)

@Serializable
data class NewUserResponse(
    val version: String
)

// ---- POST /internal/keys/derive ----

@Serializable //das was reinkommt
data class GetKeyRequest(
    val userId: String,
    val version: Int? = null,
    val alg: String
)

@Serializable //das was rausgeht
data class GetKeyResponse(
    val key: String,
    val version: Int
)
