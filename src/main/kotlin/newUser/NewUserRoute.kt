package de.trustylynx.newUser

import de.trustylynx.keyValidation.Validate
import de.trustylynx.pepperhmac.PepperHmacResponse
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable   // für @Serializable an den DTOs
import kotlin.io.encoding.Base64

@Serializable
data class userKeyVersion(
    val keyVersion: String
)

fun Route.newUserRoute() {
    post("/internal/users/{userId}/keys"){
        val user = call.parameters["userId"] ?: return@post
        // 1. Token prüfen, noch bevor der Body gelesen wird
        if (!Validate.authService(call)) return@post
        if(newUserId(user)){
            createNewUser(user)
            call.respond(userKeyVersion("1"))
        }
        else{
            call.respond(HttpStatusCode.Conflict, mapOf("error" to "user_already_exists"))
            return@post
        }
    }
}