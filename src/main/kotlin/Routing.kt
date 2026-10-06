package de.trustylynx

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

import de.trustylynx.pepperhmac.pepperHmacRoute

fun Application.configureRouting() {
    routing {
        get("/test") {
            call.respondText("Hello, World!")
        }
        pepperHmacRoute()
    }
}