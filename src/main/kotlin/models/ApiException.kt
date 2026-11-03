package de.trustylynx.models

import io.ktor.http.HttpStatusCode

// no stack trace, these only ever turn into a response
open class ApiException(
    val status: HttpStatusCode,
    val code: String,
    val reason: String? = null,
) : RuntimeException(code, null, false, false)

class BadRequest(reason: String) : ApiException(HttpStatusCode.BadRequest, "bad_request", reason)

class Unauthorized : ApiException(HttpStatusCode.Unauthorized, "unauthorized")

class Forbidden : ApiException(HttpStatusCode.Forbidden, "forbidden")

class NotFound : ApiException(HttpStatusCode.NotFound, "not_found")

class AlreadyExists : ApiException(HttpStatusCode.Conflict, "already_exists")

class IntegrityError : ApiException(HttpStatusCode.InternalServerError, "integrity_error")
