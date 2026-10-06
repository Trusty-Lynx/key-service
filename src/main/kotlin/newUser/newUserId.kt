package de.trustylynx.newUser

import java.sql.Connection


fun newUserId(userId: String): Boolean =
    dataSource.connection.use { conn ->
        conn.prepareStatement(
            "SELECT EXISTS (SELECT 1 FROM server_keys WHERE user_id = ? AND active = true)"
        ).use { stmt ->
            stmt.setString(1, userId)
            stmt.executeQuery().use { rs -> rs.next() && rs.getBoolean(1) }

        }
    }