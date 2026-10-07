package de.trustylynx.newUser

import de.trustylynx.keyValidation.Validate
import de.trustylynx.pepperhmac.PepperHmacRequest
import de.trustylynx.pepperhmac.PepperHmacResponse
import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable   // für @Serializable an den DTOs
import kotlin.io.encoding.Base64

@Serializable
data class NewUserRequest(
    val userId: String
)
@Serializable
data class NewUserResponse(
    val keyVersion: String
)

fun Route.newUserRoute() {
    post("/internal/users/create"){
        val receive = try {
            call.receive<NewUserRequest>() //weil das nirgendwo festgelegt wird wird hier gesagt dass es das ist was rein kommt
        } catch (e: BadRequestException) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "bad_request"))
            return@post
        }
        val user = receive.userId
        // 1. Token prüfen, noch bevor der Body gelesen wird
        if (!Validate.authService(call)) return@post
        if(newUserId(user)){
            createNewUser(user)
            call.respond(NewUserResponse("1"))
        }
        else{
            call.respond(HttpStatusCode.Conflict, mapOf("error" to "user_already_exists"))
            return@post
        }
    }
}