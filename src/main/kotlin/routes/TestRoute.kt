package de.trustylynx.routes

import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

fun Route.testRoute() {
    get("/test") { call.respondText("Hello, World!") }
}
