package de.trustylynx.models

import kotlinx.serialization.Serializable

// the field names and their order are the API, don't change them

@Serializable
data class PepperHmacRequest(val purpose: String, val userId: String, val key: String) {
    // without the key, so it never ends up in a log
    override fun toString() = "PepperHmacRequest(purpose=$purpose, userId=$userId)"
}

@Serializable
data class PepperHmacResponse(val h: String) {
    // h is the input for the verifier, so it never ends up in a log either
    override fun toString() = "PepperHmacResponse(h=***)"
}

@Serializable
data class NewUserRequest(val userId: String)

@Serializable
data class NewUserResponse(val version: String)

@Serializable
data class GetKeyRequest(val userId: String, val version: Int? = null, val alg: String)

@Serializable
data class GetKeyResponse(val key: String, val version: Int) {
    // without the derived key, so it never ends up in a log
    override fun toString() = "GetKeyResponse(version=$version)"
}

@Serializable
data class ErrorResponse(val error: String, val reason: String? = null)
