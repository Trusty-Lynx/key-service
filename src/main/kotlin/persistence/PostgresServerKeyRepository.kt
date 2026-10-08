package de.trustylynx.persistence

import de.trustylynx.common.AlreadyExists
import de.trustylynx.common.withConnection
import java.sql.SQLException
import javax.sql.DataSource

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
                    statement.setBytes(3, wrappedSdk)   // 60 echte Bytes → BYTEA
                    statement.executeUpdate()
                }
            } catch (e: SQLException) {
                // Primary Key (user_id, version) verletzt → Nutzer hat schon Schlüssel
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

    private companion object {
        const val UNIQUE_VIOLATION = "23505"
    }
}
