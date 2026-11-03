package de.trustylynx.repositories

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.sql.Connection
import javax.sql.DataSource

private const val POOL_NAME = "key-db"
private const val MAX_POOL_SIZE = 10

class DbConfig(val url: String, val user: String, val password: String)

fun createDataSource(config: DbConfig): HikariDataSource {
    val hikari = HikariConfig()
    hikari.poolName = POOL_NAME
    hikari.jdbcUrl = config.url
    hikari.username = config.user
    hikari.password = config.password
    hikari.maximumPoolSize = MAX_POOL_SIZE
    return HikariDataSource(hikari)
}

// jdbc blocks the thread while it waits, so this has to run on the IO pool
suspend fun <T> DataSource.withConnection(block: (Connection) -> T): T =
    withContext(Dispatchers.IO) { connection.use(block) }
