package de.trustylynx.routes

import de.trustylynx.Secrets
import de.trustylynx.models.BadRequest
import de.trustylynx.models.GetKeyRequest
import de.trustylynx.models.NewUserRequest
import de.trustylynx.models.PepperHmacRequest
import de.trustylynx.models.PepperHmacResponse
import de.trustylynx.security.pepperHmac
import de.trustylynx.services.ServerKeyService
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlin.io.encoding.Base64

// every route checks the token before the body, so a broken body without a token still gets a 401
fun Route.internalRoutes(serverKeys: ServerKeyService) {
    post("/internal/pepper-hmac") {
        val tokenPurpose = call.requirePurposeToken()
        val request = call.receive<PepperHmacRequest>()
        validatePurpose(tokenPurpose, request.purpose)
        val key = validateKey(request.key)

        val pepper = if (tokenPurpose == "login") Secrets.pepperLogin else Secrets.pepperVault
        call.respond(PepperHmacResponse(h = Base64.encode(pepperHmac(pepper, key))))
    }

    post("/internal/users/create") {
        call.requireAuthServiceToken()

        val request = call.receive<NewUserRequest>()
        if (request.userId.isBlank()) throw BadRequest("userId missing")

        val response = serverKeys.createForNewUser(request.userId)

        // TODO: switch to 201 Created once auth checks isSuccess()
        call.respond(HttpStatusCode.Created, response)
    }

    post("/internal/keys/derive") {
        val tokenAlg = call.requireCryptoToken()
        val request = call.receive<GetKeyRequest>()
        validateAlg(tokenAlg, request.alg)
        if (request.userId.isBlank()) throw BadRequest("userId missing")

        call.respond(serverKeys.derive(request.userId, request.version, tokenAlg))
    }
}
