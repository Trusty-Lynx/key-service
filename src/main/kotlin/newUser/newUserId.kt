package de.trustylynx.newUser
import de.trustylynx.secureUserKey.*

import java.io.File
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64
import java.security.SecureRandom
import java.nio.charset.Charset
import de.trustylynx.Secrets

// NUR ZUM TESTEN – später kommt das in die Datenbank (Tabelle server_keys)
private val keysFile = File("data/serverKeys.json")

// Lock-Objekt: Ktor bearbeitet Requests parallel, damit nicht zwei gleichzeitig in die Datei schreiben
private val lock = Any()

private val json = Json { prettyPrint = true}
// true = userId ist NEU (steht noch nicht als aktiv in der Datei)
fun newUserId(userId: String): Boolean = synchronized(lock) {
    if (!keysFile.exists()) return@synchronized true   // keine Datei → noch gar keine User → neu
    val list: List<ServerKey>  = json.decodeFromString(keysFile.readText())
    list.none { it.userId == userId && it.active }
}

// userId als aktiv ans Ende der Datei hängen
fun createNewUser(userId: String) = synchronized(lock) {
    val list: List<ServerKey> = json.decodeFromString(keysFile.readText())
    val sdkU = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val aad: ByteArray = "$userId:1".toByteArray(Charset.forName("UTF-8"))
    val key = Base64.encode(wrapKey(Secrets.msk, sdkU, aad ))

    keysFile.writeText(json.encodeToString( list + ServerKey(userId, 1, key, true)))

}


/*dataSource.connection.use { conn ->
    conn.prepareStatement(
        "SELECT EXISTS (SELECT 1 FROM server_keys WHERE user_id = ? AND active = true)"
    ).use { stmt ->
        stmt.setString(1, userId)
        stmt.executeQuery().use { rs -> rs.next() && rs.getBoolean(1) }

    }
}*/