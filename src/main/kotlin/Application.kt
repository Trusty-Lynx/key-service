package de.trustylynx

import de.trustylynx.plugins.configureSerialization
import de.trustylynx.plugins.configureStatusPages
import de.trustylynx.repositories.PostgresServerKeyRepository
import de.trustylynx.repositories.createDataSource
import de.trustylynx.repositories.isReachable
import de.trustylynx.routes.healthRoute
import de.trustylynx.routes.internalRoutes
import de.trustylynx.services.ServerKeyService
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopped
import io.ktor.server.netty.EngineMain
import io.ktor.server.routing.routing

fun main(args: Array<String>) {
    EngineMain.main(args)
}

fun Application.module() {
    val config = AppConfig.fromEnv()

    val dataSource = createDataSource(config.db)
    monitor.subscribe(ApplicationStopped) { dataSource.close() }

    val serverKeys = ServerKeyService(PostgresServerKeyRepository(dataSource), Secrets.msk)

    configureApp(serverKeys) { dataSource.isReachable() }
}

// separate from module() so the tests can start the app with fakes instead of a real db
fun Application.configureApp(
    serverKeys: ServerKeyService,
    isHealthy: suspend () -> Boolean = { true },
) {
    configureSerialization()
    configureStatusPages()
    routing {
        healthRoute(isHealthy)
        internalRoutes(serverKeys)
    }
}
