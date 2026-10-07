package de.trustylynx.pepperhmac

import de.trustylynx.Secrets
import de.trustylynx.keyValidation.Validate
import io.ktor.http.HttpStatusCode // STATUSCODES (400, 401, ...)
import io.ktor.server.request.*    // EINLESEN
import io.ktor.server.response.*   // ANTWORTEN
import io.ktor.server.routing.*    // URL ZUORDNEN
import kotlinx.serialization.Serializable   // für @Serializable an den DTOs
import kotlin.io.encoding.Base64 //dass er mit base64 rechnen kann
import io.ktor.server.plugins.BadRequestException // für kaputtes JSON / fehlende Felder


@Serializable //das was reinkommt
data class PepperHmacRequest(
    val purpose: String,
    val userId: String,
    val key: String
)

@Serializable //das was rausgeht
data class PepperHmacResponse(
    val h: String
)

fun Route.pepperHmacRoute(){
    post("/internal/pepper-hmac"){
        //Hier eigentlich möglichst wenig Logik reinmachen. Auslagern in Servive/Manager
        // 1. Token prüfen, noch bevor der Body gelesen wird
        val tokenPurpose = Validate.service(call) ?: return@post

        // 2. Body lesen; kaputtes JSON oder fehlendes Feld → 400 statt Ktor-eigener Fehlermeldung
        val receive = try {
            call.receive<PepperHmacRequest>() //weil das nirgendwo festgelegt wird wird hier gesagt dass es das ist was rein kommt
        } catch (e: BadRequestException) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "bad_request"))
            return@post
        }

        // 3. Unbekannter purpose → 400
        if(receive.purpose != "login" && receive.purpose != "vault"){ //wird geprüft ob es auch das ist was der anfrager haben will wenn er einen anderen purpose schickt dann gebe ich zurück dass ich das nicht mache
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "bad_request"))
            return@post
        }

        // 4. Token ist gültig, gehört aber zum anderen Service (z.B. Auth-Service fragt vault an) → 403
        if (receive.purpose != tokenPurpose) {
            call.respond(HttpStatusCode.Forbidden, mapOf("error" to "forbidden"))
            return@post
        }

        val key = try { Base64.decode(receive.key) } catch (e: IllegalArgumentException) { null }
        if(key == null || key.size != 32){
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "bad_request"))
            return@post
        }

        val pepper = if(receive.purpose == "login") Secrets.pepperLogin else Secrets.pepperVault
        val h= pepperHmac(pepper, key) //Rechnen

        call.respond(PepperHmacResponse(h= Base64.encode(h)))
    }
}
