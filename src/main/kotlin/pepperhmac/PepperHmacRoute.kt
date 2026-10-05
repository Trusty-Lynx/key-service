package de.trustylynx.pepperhmac

import io.ktor.server.request.*    // EINLESEN
import io.ktor.server.response.*   // ANTWORTEN
import io.ktor.server.routing.*    // URL ZUORDNEN
import kotlinx.serialization.Serializable   // für @Serializable an den DTOs

@Serializable //das was reinkommt
data class PepperHmacRequest(val purpose: String, val userId: String, val key: String)

@Serializable //das was rausgeht
data class PepperHmacResponse(val h: String)

fun Route.pepperHmacRoute(){
    post("/internal/pepper-hmac"){
        val receive = call.receive<PepperHmacRequest>() //weil das nirgendwo festgelegt wird wird hier gesagt dass es das ist was rein kommt

        if(receive.purpose != "login" && req.purpose != "vault"){ //wird geprüft ob es auch das ist was der anfrager haben will wenn er einen anderen purpose schickt dann gebe ich zurück dass ich das nicht mache

        }

        if

    }
}
