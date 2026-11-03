package de.trustylynx.plugins

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation

fun Application.configureSerialization() {
    install(ContentNegotiation) {
        // plain json() on purpose, unlike AppJson in the auth service. errors go out with "reason":null because of it
        json()
    }
}
