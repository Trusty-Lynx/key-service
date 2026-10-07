package de.trustylynx.keyValidation

import de.trustylynx.Secrets
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond
import java.security.MessageDigest

object Validate {

    // Prüft den X-Service-Token Header.
    // Gültig → gibt den purpose zurück ("login" / "vault")
    // Ungültig/fehlt → antwortet selbst mit 401 und gibt null zurück
    suspend fun service(call: ApplicationCall): String? {
        val token = call.request.headers["X-Service-Token"]
        val purpose = token?.let { purposeForToken(it) }
        if (purpose == null) {
            call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "unauthorized"))
        }
        return purpose
    }

    // Nur der Auth-Service darf durch. Fehlt/falsch → 401, gibt false zurück
    suspend fun authService(call: ApplicationCall): Boolean {
        val token = call.request.headers["X-Service-Token"]
        // isEqual vergleicht in konstanter Zeit (gegen Timing-Angriffe)
        val ok = token != null &&
                MessageDigest.isEqual(token.toByteArray(), Secrets.authServiceToken.toByteArray())
        if (!ok) call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "unauthorized"))
        return ok
    }


    // Gibt zurück, für welchen purpose das Token gilt, oder null wenn es zu keinem passt
    private fun purposeForToken(token: String): String? {
        val t = token.toByteArray()
        // isEqual vergleicht in konstanter Zeit, damit man das Token nicht über Timing erraten kann
        return when {
            MessageDigest.isEqual(t, Secrets.authServiceToken.toByteArray()) -> "login"
            MessageDigest.isEqual(t, Secrets.vaultServiceToken.toByteArray()) -> "vault"
            else -> null
        }
    }
}
