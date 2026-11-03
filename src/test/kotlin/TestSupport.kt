package de.trustylynx

import de.trustylynx.models.AlreadyExists
import de.trustylynx.services.ServerKeyService
import de.trustylynx.repositories.ServerKeyRepository
import de.trustylynx.models.WrappedKey
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.HexFormat
import java.util.concurrent.ConcurrentHashMap

// tokens and peppers have to match tasks.test in build.gradle.kts, Secrets reads them from the environment
const val AUTH_TOKEN = "test-auth-token"
const val VAULT_TOKEN = "test-vault-token"
const val AES_TOKEN = "test-aes-token"
const val CHACHA_TOKEN = "test-chacha-token"
const val PEPPER_LOGIN = "pepper-login-test-value-32-bytes"
const val PEPPER_VAULT = "pepper-vault-test-value-32-bytes"

// not the same as Secrets.msk on purpose
val TEST_MSK = ByteArray(32) { 9 }

fun withApp(
    repo: InMemoryServerKeyRepository = InMemoryServerKeyRepository(),
    block: suspend (HttpClient) -> Unit,
) = testApplication {
    // empty config, otherwise application.yaml would load module() with the real db
    environment { config = MapApplicationConfig() }
    application { configureApp(ServerKeyService(repo, TEST_MSK)) }
    block(client)
}

suspend fun HttpClient.postJson(path: String, body: String, token: String? = null): HttpResponse = post(path) {
    contentType(ContentType.Application.Json)
    if (token != null) header("X-Service-Token", token)
    setBody(body)
}

suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject

suspend fun HttpResponse.errorCode(): String = json()["error"]!!.jsonPrimitive.content

fun hex(s: String): ByteArray = HexFormat.of().parseHex(s)

fun b64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

fun unb64(s: String): ByteArray = java.util.Base64.getDecoder().decode(s)

// every row counts as active here, the highest version wins
class InMemoryServerKeyRepository : ServerKeyRepository {
    val rows = ConcurrentHashMap<Pair<String, Int>, ByteArray>()

    override suspend fun create(userId: String, version: Int, wrappedSdk: ByteArray) {
        if (rows.putIfAbsent(userId to version, wrappedSdk) != null) throw AlreadyExists()
    }

    override suspend fun find(userId: String, version: Int?): WrappedKey? {
        val v = version ?: rows.keys.filter { it.first == userId }.maxOfOrNull { it.second } ?: return null
        val wrapped = rows[userId to v] ?: return null
        return WrappedKey(v, wrapped)
    }
}
