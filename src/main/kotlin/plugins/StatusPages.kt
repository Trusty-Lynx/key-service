package de.trustylynx.plugins

import de.trustylynx.models.ApiException
import de.trustylynx.models.ErrorResponse
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.engine.defaultExceptionStatusCode
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respond

fun Application.configureStatusPages() {
    install(StatusPages) {
        exception<ApiException> { call, cause ->
            call.respond(cause.status, ErrorResponse(cause.code, cause.reason))
        }
        exception<BadRequestException> { call, _ ->
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("bad_request", "malformed request body"))
        }
        exception<Throwable> { call, cause ->
            // stuff ktor already has a status for, like 415 for a wrong content type
            val status = defaultExceptionStatusCode(cause)
            if (status != null) {
                call.respond(status, ErrorResponse(status.description.lowercase().replace(' ', '_')))
            } else {
                call.application.log.error("Unhandled error on ${call.request.httpMethod.value} ${call.request.path()}", cause)
                call.respond(HttpStatusCode.InternalServerError, ErrorResponse("internal_error"))
            }
        }
    }
}
