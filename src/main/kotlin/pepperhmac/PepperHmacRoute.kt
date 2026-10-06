package de.trustylynx.pepperhmac


import io.ktor.http.HttpStatusCode // STATUSCODES (400, 401, ...)
import io.ktor.server.request.*    // EINLESEN
import io.ktor.server.response.*   // ANTWORTEN
import io.ktor.server.routing.*    // URL ZUORDNEN
import kotlinx.serialization.Serializable   // für @Serializable an den DTOs
import kotlin.io.encoding.Base64 //dass er mit base64 rechnen kann
import de.trustylynx.newUser.*

@Serializable //das was reinkommt
data class PepperHmacRequest(val purpose: String, val userId: String, val key: String)

@Serializable //das was rausgeht
data class PepperHmacResponse(val h: String)

fun Route.pepperHmacRoute(){
    post("/internal/pepper-hmac"){
        val receive = call.receive<PepperHmacRequest>() //weil das nirgendwo festgelegt wird wird hier gesagt dass es das ist was rein kommt

        if(receive.purpose != "login" && receive.purpose != "vault"){ //wird geprüft ob es auch das ist was der anfrager haben will wenn er einen anderen purpose schickt dann gebe ich zurück dass ich das nicht mache
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "bad_request"))
            return@post
        }
        val key = try { Base64.decode(receive.key) } catch (e: IllegalArgumentException) { null }
        if(key == null || key.size != 32){
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "bad_request"))
            return@post
        }

        val pepper = if(receive.purpose == "login") TEST_PEPPER_LOGIN else TEST_PEPPER_VAULT
        /*if(receive.purpose=="login"){
            serviceId = "1"
            if(receive.serviceId != serviceId){
                //Fehlercode
                return@post
            }
            pepper = [1,2]
        } else{
            serviceId ="2"
            if(receive.serviceId != serviceId){
                //Fehlercode
                return@post

            }
            pepper = [1,2]
        }*/
        if(newUserId(receive.userId)){createNewUser()}
        val h= pepperHmac(pepper, key) //Rechnen

        call.respond(PepperHmacResponse(h= Base64.encode(h)))
    }
}
