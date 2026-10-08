package de.trustylynx.api

import de.trustylynx.common.BadRequest
import de.trustylynx.common.Validate
import de.trustylynx.domain.ServerKeyService
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

fun Route.newUserRoute(serverKeys: ServerKeyService) {
    post("/internal/users/create") {
        // 1. Token prüfen, noch bevor der Body gelesen wird
        Validate.authService(call)

        // Kaputtes JSON / fehlendes Feld → BadRequestException → StatusPages → 400
        val request = call.receive<NewUserRequest>()
        if (request.userId.isBlank()) throw BadRequest("userId missing")

        // Gibt es schon → AlreadyExists → StatusPages → 409 already_exists
        val version = serverKeys.createForNewUser(request.userId)

        // TODO: auf 201 Created umstellen, sobald Auth isSuccess() prüft
        call.respond(HttpStatusCode.Created, NewUserResponse(version.toString()))
    }
}
