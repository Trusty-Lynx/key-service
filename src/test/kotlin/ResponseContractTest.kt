package de.trustylynx

import de.trustylynx.security.K_AES_V8
import de.trustylynx.security.K_CHACHA_V8
import de.trustylynx.security.SDK_U_V8
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals

// pins the exact bytes clients get, including "reason":null and which error wins when several things are wrong
class ResponseContractTest {

    @Test
    fun `GET test says hello`() = withApp { client ->
        val response = client.get("/test")

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("Hello, World!", response.bodyAsText())
        assertEquals("text/plain; charset=UTF-8", response.headers[HttpHeaders.ContentType])
    }

    @Test
    fun `unknown path gives an empty 404`() = withApp { client ->
        val response = client.get("/internal/nope")

        assertEquals(HttpStatusCode.NotFound, response.status)
        assertEquals("", response.bodyAsText())
    }

    @Test
    fun `wrong method gives an empty 405`() = withApp { client ->
        for (path in listOf(PEPPER, CREATE, DERIVE)) {
            val response = client.get(path)

            assertEquals(HttpStatusCode.MethodNotAllowed, response.status)
            assertEquals("", response.bodyAsText())
        }
    }

    @Test
    fun `pepper-hmac success`() = withApp { client ->
        // HMAC-SHA256 over 32 zero bytes with the pepper from tasks.test in build.gradle.kts
        client.postJson(PEPPER, pepperBody("login", ZERO_KEY), AUTH_TOKEN).assertExact(
            HttpStatusCode.OK,
            """{"h":"$H_LOGIN_ZERO_KEY"}""",
        )
        client.postJson(PEPPER, pepperBody("vault", ZERO_KEY), VAULT_TOKEN).assertExact(
            HttpStatusCode.OK,
            """{"h":"$H_VAULT_ZERO_KEY"}""",
        )
    }

    @Test
    fun `pepper-hmac errors`() = withApp { client ->
        client.postJson(PEPPER, pepperBody("login", ZERO_KEY)).assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        client.postJson(PEPPER, pepperBody("login", ZERO_KEY), "wrong").assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        // crypto tokens are not valid here at all, so 401 and not 403
        client.postJson(PEPPER, pepperBody("login", ZERO_KEY), AES_TOKEN).assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        client.postJson(PEPPER, pepperBody("login", ZERO_KEY), CHACHA_TOKEN).assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        client.postJson(PEPPER, pepperBody("vault", ZERO_KEY), AUTH_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
        client.postJson(PEPPER, pepperBody("login", ZERO_KEY), VAULT_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
        client.postJson(PEPPER, pepperBody("foo", ZERO_KEY), AUTH_TOKEN)
            .assertExact(HttpStatusCode.BadRequest, badRequest("unknown purpose"))
        client.postJson(PEPPER, pepperBody("login", "not base64!"), AUTH_TOKEN)
            .assertExact(HttpStatusCode.BadRequest, badRequest("key is not base64"))
        client.postJson(PEPPER, pepperBody("login", b64(ByteArray(31))), AUTH_TOKEN)
            .assertExact(HttpStatusCode.BadRequest, badRequest("key must be 32 bytes"))
        client.postJson(PEPPER, pepperBody("login", b64(ByteArray(33))), AUTH_TOKEN)
            .assertExact(HttpStatusCode.BadRequest, badRequest("key must be 32 bytes"))
        client.postJson(PEPPER, """{"purpose":""", AUTH_TOKEN).assertExact(HttpStatusCode.BadRequest, MALFORMED)
        client.postJson(PEPPER, """{"purpose":"login","userId":"u42"}""", AUTH_TOKEN).assertExact(HttpStatusCode.BadRequest, MALFORMED)
        // no ignoreUnknownKeys, an extra field is a broken request
        client.postJson(PEPPER, """{"purpose":"login","userId":"u42","key":"$ZERO_KEY","x":1}""", AUTH_TOKEN)
            .assertExact(HttpStatusCode.BadRequest, MALFORMED)
    }

    @Test
    fun `pepper-hmac check order`() = withApp { client ->
        // token before body
        client.postJson(PEPPER, "not json").assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        // unknown purpose before a purpose that belongs to someone else, purpose before key
        client.postJson(PEPPER, pepperBody("foo", "not base64!"), VAULT_TOKEN)
            .assertExact(HttpStatusCode.BadRequest, badRequest("unknown purpose"))
        client.postJson(PEPPER, pepperBody("login", "not base64!"), VAULT_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
    }

    @Test
    fun `create success`() = withApp { client ->
        client.postJson(CREATE, """{"userId":"u1"}""", AUTH_TOKEN).assertExact(HttpStatusCode.Created, """{"version":"1"}""")
    }

    @Test
    fun `create errors`() = withApp { client ->
        val body = """{"userId":"u1"}"""
        client.postJson(CREATE, body).assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        client.postJson(CREATE, body, "wrong").assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        client.postJson(CREATE, body, VAULT_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
        client.postJson(CREATE, body, AES_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
        client.postJson(CREATE, body, CHACHA_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
        client.postJson(CREATE, """{"userId":"  "}""", AUTH_TOKEN).assertExact(HttpStatusCode.BadRequest, badRequest("userId missing"))
        client.postJson(CREATE, """{"userId":""", AUTH_TOKEN).assertExact(HttpStatusCode.BadRequest, MALFORMED)
        client.postJson(CREATE, "{}", AUTH_TOKEN).assertExact(HttpStatusCode.BadRequest, MALFORMED)

        client.postJson(CREATE, body, AUTH_TOKEN).assertExact(HttpStatusCode.Created, """{"version":"1"}""")
        client.postJson(CREATE, body, AUTH_TOKEN).assertExact(HttpStatusCode.Conflict, """{"error":"already_exists","reason":null}""")
    }

    @Test
    fun `create check order`() = withApp { client ->
        // token before body, also for tokens of other services
        client.postJson(CREATE, "not json").assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        client.postJson(CREATE, "not json", VAULT_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
    }

    @Test
    fun `derive success has key first and version second`() = withApp(repoWithV8()) { client ->
        client.postJson(DERIVE, deriveBody("u42", "aes"), AES_TOKEN)
            .assertExact(HttpStatusCode.OK, """{"key":"${b64(K_AES_V8)}","version":1}""")
        client.postJson(DERIVE, """{"userId":"u42","version":1,"alg":"chacha"}""", CHACHA_TOKEN)
            .assertExact(HttpStatusCode.OK, """{"key":"${b64(K_CHACHA_V8)}","version":1}""")
    }

    @Test
    fun `derive errors`() = withApp(repoWithV8()) { client ->
        val body = deriveBody("u42", "aes")
        client.postJson(DERIVE, body).assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        client.postJson(DERIVE, body, "wrong").assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        // auth and vault tokens are not valid here at all, so 401 and not 403
        client.postJson(DERIVE, body, AUTH_TOKEN).assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        client.postJson(DERIVE, body, VAULT_TOKEN).assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        client.postJson(DERIVE, body, CHACHA_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
        client.postJson(DERIVE, deriveBody("u42", "chacha"), AES_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
        client.postJson(DERIVE, deriveBody("u42", "des"), AES_TOKEN).assertExact(HttpStatusCode.BadRequest, badRequest("unknown alg"))
        client.postJson(DERIVE, deriveBody(" ", "aes"), AES_TOKEN).assertExact(HttpStatusCode.BadRequest, badRequest("userId missing"))
        client.postJson(DERIVE, """{"userId":""", AES_TOKEN).assertExact(HttpStatusCode.BadRequest, MALFORMED)
        client.postJson(DERIVE, deriveBody("u99", "aes"), AES_TOKEN).assertExact(HttpStatusCode.NotFound, NOT_FOUND)
        client.postJson(DERIVE, """{"userId":"u42","version":99,"alg":"aes"}""", AES_TOKEN).assertExact(HttpStatusCode.NotFound, NOT_FOUND)
    }

    @Test
    fun `derive check order`() = withApp(repoWithV8()) { client ->
        // token before body
        client.postJson(DERIVE, "not json").assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
        // unknown alg before foreign alg, alg before userId
        client.postJson(DERIVE, deriveBody(" ", "des"), CHACHA_TOKEN).assertExact(HttpStatusCode.BadRequest, badRequest("unknown alg"))
        client.postJson(DERIVE, deriveBody(" ", "aes"), CHACHA_TOKEN).assertExact(HttpStatusCode.Forbidden, FORBIDDEN)
    }

    @Test
    fun `derive with a damaged key gives integrity_error`() {
        val repo = repoWithV8()
        repo.rows["short" to 1] = ByteArray(59)

        withApp(repo) { client ->
            client.postJson(DERIVE, deriveBody("short", "aes"), AES_TOKEN)
                .assertExact(HttpStatusCode.InternalServerError, """{"error":"integrity_error","reason":null}""")
        }
    }

    @Test
    fun `wrong content type gives 415 after the token check`() = withApp { client ->
        val unsupported = """{"error":"unsupported_media_type","reason":null}"""
        client.postText(PEPPER, "{}", AUTH_TOKEN).assertExact(HttpStatusCode.UnsupportedMediaType, unsupported)
        client.postText(CREATE, "{}", AUTH_TOKEN).assertExact(HttpStatusCode.UnsupportedMediaType, unsupported)
        client.postText(DERIVE, "{}", AES_TOKEN).assertExact(HttpStatusCode.UnsupportedMediaType, unsupported)
        client.postText(PEPPER, "{}", token = null).assertExact(HttpStatusCode.Unauthorized, UNAUTHORIZED)
    }

    private fun repoWithV8() = InMemoryServerKeyRepository().apply {
        rows["u42" to 1] = wrapForTest("u42", 1)
    }

    private suspend fun HttpClient.postText(path: String, body: String, token: String?): HttpResponse = post(path) {
        contentType(ContentType.Text.Plain)
        if (token != null) header("X-Service-Token", token)
        setBody(body)
    }

    private suspend fun HttpResponse.assertExact(status: HttpStatusCode, body: String) {
        assertEquals(status, this.status)
        assertEquals(body, bodyAsText())
        assertEquals("application/json", headers[HttpHeaders.ContentType])
    }

    private fun pepperBody(purpose: String, key: String) = """{"purpose":"$purpose","userId":"u42","key":"$key"}"""

    private fun deriveBody(userId: String, alg: String) = """{"userId":"$userId","alg":"$alg"}"""

    private fun badRequest(reason: String) = """{"error":"bad_request","reason":"$reason"}"""
}

private const val PEPPER = "/internal/pepper-hmac"
private const val CREATE = "/internal/users/create"
private const val DERIVE = "/internal/keys/derive"

private const val UNAUTHORIZED = """{"error":"unauthorized","reason":null}"""
private const val FORBIDDEN = """{"error":"forbidden","reason":null}"""
private const val NOT_FOUND = """{"error":"not_found","reason":null}"""
private const val MALFORMED = """{"error":"bad_request","reason":"malformed request body"}"""

private val ZERO_KEY = b64(ByteArray(32))
private val H_LOGIN_ZERO_KEY = hmacForTest(PEPPER_LOGIN)
private val H_VAULT_ZERO_KEY = hmacForTest(PEPPER_VAULT)

private fun hmacForTest(pepper: String): String {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(pepper.toByteArray(), "HmacSHA256"))
    return b64(mac.doFinal(ByteArray(32)))
}

// independent of wrapKey() and the aad helper, so this also pins the stored format and the AAD string
private fun wrapForTest(userId: String, version: Int): ByteArray {
    val nonce = ByteArray(12) { 7 }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(TEST_MSK, "AES"), GCMParameterSpec(128, nonce))
    cipher.updateAAD("TL-KEY|$userId|v$version".toByteArray())
    return nonce + cipher.doFinal(SDK_U_V8)
}
