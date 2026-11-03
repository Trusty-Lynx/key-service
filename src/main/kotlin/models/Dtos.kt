package de.trustylynx.models

import kotlinx.serialization.Serializable

// the field names and their order are the API, don't change them

@Serializable
data class PepperHmacRequest(val purpose: String, val userId: String, val key: String)

@Serializable
data class PepperHmacResponse(val h: String)

@Serializable
data class NewUserRequest(val userId: String)

@Serializable
data class NewUserResponse(val version: String)

@Serializable
data class GetKeyRequest(val userId: String, val version: Int? = null, val alg: String)

@Serializable
data class GetKeyResponse(val key: String, val version: Int)

@Serializable
data class ErrorResponse(val error: String, val reason: String? = null)
