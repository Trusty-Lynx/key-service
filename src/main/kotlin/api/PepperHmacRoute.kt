package de.trustylynx.api

import de.trustylynx.common.Secrets
import de.trustylynx.common.Validate
import de.trustylynx.security.pepperHmac
import io.ktor.server.request.*    // EINLESEN
import io.ktor.server.response.*   // ANTWORTEN
import io.ktor.server.routing.*    // URL ZUORDNEN
import kotlin.io.encoding.Base64 //dass er mit base64 rechnen kann

fun Route.pepperHmacRoute(){
    post("/internal/pepper-hmac") {
        val tokenPurpose = Validate.service(call)
        val req = call.receive<PepperHmacRequest>()
        Validate.purpose(tokenPurpose, req.purpose)
        val key = Validate.key(req.key)

        val pepper = if (tokenPurpose == "login") Secrets.pepperLogin else Secrets.pepperVault
        call.respond(PepperHmacResponse(h = Base64.encode(pepperHmac(pepper, key))))
    }
}
