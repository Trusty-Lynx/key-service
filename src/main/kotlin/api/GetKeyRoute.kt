package de.trustylynx.api

import de.trustylynx.common.BadRequest
import de.trustylynx.common.Validate
import de.trustylynx.domain.ServerKeyService
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlin.io.encoding.Base64

fun Route.getKeyRoute(serverKeys: ServerKeyService) {
    post("/internal/keys/derive") {
        val tokenAlg = Validate.crypto(call)
        val receive = call.receive<GetKeyRequest>() //weil das nirgendwo festgelegt wird wird hier gesagt dass es das ist was rein kommt
        Validate.alg(tokenAlg, receive.alg)
        if (receive.userId.isBlank()) throw BadRequest("userId missing")

        val derived = serverKeys.derive(receive.userId, receive.version, tokenAlg)
        val key = try { Base64.encode(derived.key) } finally { derived.key.fill(0) }
        call.respond(GetKeyResponse(key, derived.version))
    }
}
