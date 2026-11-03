package de.trustylynx.repositories

import de.trustylynx.models.AlreadyExists
import de.trustylynx.models.WrappedKey
import java.sql.SQLException
import javax.sql.DataSource

private const val UNIQUE_VIOLATION = "23505"

interface ServerKeyRepository {
    suspend fun create(userId: String, version: Int, wrappedSdk: ByteArray)

    // version null means the active key
    suspend fun find(userId: String, version: Int?): WrappedKey?
}

class PostgresServerKeyRepository(private val dataSource: DataSource) : ServerKeyRepository {

    override suspend fun create(userId: String, version: Int, wrappedSdk: ByteArray) {
        dataSource.withConnection { connection ->
            try {
                connection.prepareStatement(
                    """
                    INSERT INTO server_keys (user_id, version, wrapped_sdk, active)
                    VALUES (?, ?, ?, true)
                    """.trimIndent(),
                ).use { statement ->
                    statement.setString(1, userId)
                    statement.setInt(2, version)
                    statement.setBytes(3, wrappedSdk)
                    statement.executeUpdate()
                }
            } catch (e: SQLException) {
                // primary key (user_id, version) is taken, so this user already has keys
                if (e.sqlState == UNIQUE_VIOLATION) throw AlreadyExists()
                throw e
            }
        }
    }

    override suspend fun find(userId: String, version: Int?): WrappedKey? =
        dataSource.withConnection { connection ->
            val sql = if (version == null) {
                "SELECT version, wrapped_sdk FROM server_keys WHERE user_id = ? AND active = true ORDER BY version DESC LIMIT 1"
            } else {
                "SELECT version, wrapped_sdk FROM server_keys WHERE user_id = ? AND version = ?"
            }
            connection.prepareStatement(sql).use { statement ->
                statement.setString(1, userId)
                if (version != null) statement.setInt(2, version)
                statement.executeQuery().use { rs ->
                    if (rs.next()) WrappedKey(rs.getInt("version"), rs.getBytes("wrapped_sdk")) else null
                }
            }
        }
}
