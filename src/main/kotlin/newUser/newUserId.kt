package de.trustylynx.newUser

import java.io.File

// NUR ZUM TESTEN – später kommt das in die Datenbank (Tabelle server_keys)
private val usersFile = File("data/users.properties")

// Lock-Objekt: Ktor bearbeitet Requests parallel, damit nicht zwei gleichzeitig in die Datei schreiben
private val lock = Any()

// true = userId ist NEU (steht noch nicht als aktiv in der Datei)
fun newUserId(userId: String): Boolean = synchronized(lock) {
    if (!usersFile.exists()) return@synchronized true   // keine Datei → noch gar keine User → neu
    usersFile.readLines().none { it == "$userId=active" } // keine passende Zeile gefunden → neu
}

// userId als aktiv ans Ende der Datei hängen
fun createNewUser(userId: String) = synchronized(lock) {
    usersFile.parentFile?.mkdirs()          // Ordner "data" anlegen, falls er fehlt
    usersFile.appendText("$userId=active\n") // neue Zeile anhängen (Datei wird erstellt, falls nötig)
}


/*dataSource.connection.use { conn ->
    conn.prepareStatement(
        "SELECT EXISTS (SELECT 1 FROM server_keys WHERE user_id = ? AND active = true)"
    ).use { stmt ->
        stmt.setString(1, userId)
        stmt.executeQuery().use { rs -> rs.next() && rs.getBoolean(1) }

    }
}*/