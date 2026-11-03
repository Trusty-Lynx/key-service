package de.trustylynx

import de.trustylynx.security.K_AES_V8
import de.trustylynx.security.K_CHACHA_V8
import de.trustylynx.security.SDK_U_V8
import de.trustylynx.security.wrapKey
import de.trustylynx.services.ServerKeyService
import io.ktor.http.HttpStatusCode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive

// POST /internal/keys/derive, documentation/api/key-service/derive-key.md
class GetKeyRouteTest {

    @Test
    fun `crypto 1 gets K_aes from test vector V8`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(alg = "aes"), AES_TOKEN)

        assertEquals(HttpStatusCode.OK, response.status)
        val json = response.json()
        assertContentEquals(K_AES_V8, unb64(json["key"]!!.jsonPrimitive.content))
        assertEquals(1, json["version"]!!.jsonPrimitive.int)
    }

    @Test
    fun `crypto 2 gets K_chacha from test vector V8`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(alg = "chacha"), CHACHA_TOKEN)

        assertEquals(HttpStatusCode.OK, response.status)
        assertContentEquals(K_CHACHA_V8, unb64(response.json()["key"]!!.jsonPrimitive.content))
    }

    @Test
    fun `explicit version returns the same key`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(alg = "aes", version = 1), AES_TOKEN)

        assertEquals(HttpStatusCode.OK, response.status)
        assertContentEquals(K_AES_V8, unb64(response.json()["key"]!!.jsonPrimitive.content))
    }

    @Test
    fun `missing token returns 401`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(alg = "aes"), token = null)

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("unauthorized", response.errorCode())
    }

    @Test
    fun `unknown token returns 401`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(alg = "aes"), "wrong-token")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("unauthorized", response.errorCode())
    }

    @Test
    fun `crypto 2 asking for aes returns 403`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(alg = "aes"), CHACHA_TOKEN)

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals("forbidden", response.errorCode())
    }

    @Test
    fun `crypto 1 asking for chacha returns 403`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(alg = "chacha"), AES_TOKEN)

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals("forbidden", response.errorCode())
    }

    @Test
    fun `unknown alg returns 400`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(alg = "des"), AES_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    @Test
    fun `blank userId returns 400`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(userId = " ", alg = "aes"), AES_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    @Test
    fun `malformed json returns 400`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, """{"userId":""", AES_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    @Test
    fun `unknown user returns 404`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(userId = "u99", alg = "aes"), AES_TOKEN)

        assertEquals(HttpStatusCode.NotFound, response.status)
        assertEquals("not_found", response.errorCode())
    }

    @Test
    fun `unknown version returns 404`() = withApp(repoWithV8()) { client ->
        val response = client.postJson(PATH, body(alg = "aes", version = 99), AES_TOKEN)

        assertEquals(HttpStatusCode.NotFound, response.status)
        assertEquals("not_found", response.errorCode())
    }

    @Test
    fun `tampered wrapped_sdk returns 500 integrity_error`() {
        val repo = repoWithV8()
        val wrapped = repo.rows["u42" to 1]!!
        wrapped[20] = (wrapped[20].toInt() xor 1).toByte()   // one bit changed in the db

        withApp(repo) { client ->
            val response = client.postJson(PATH, body(alg = "aes"), AES_TOKEN)

            assertEquals(HttpStatusCode.InternalServerError, response.status)
            assertEquals("integrity_error", response.errorCode())
        }
    }

    @Test
    fun `wrapped_sdk copied to another user returns 500 integrity_error`() {
        val repo = repoWithV8()
        repo.rows["u77" to 1] = repo.rows["u42" to 1]!!.copyOf()   // the aad doesn't fit u77 anymore

        withApp(repo) { client ->
            val response = client.postJson(PATH, body(userId = "u77", alg = "aes"), AES_TOKEN)

            assertEquals(HttpStatusCode.InternalServerError, response.status)
            assertEquals("integrity_error", response.errorCode())
        }
    }

    // u42 with SDK_u from test vector V8, wrapped with the test msk
    private fun repoWithV8() = InMemoryServerKeyRepository().apply {
        rows["u42" to 1] = wrapKey(TEST_MSK, SDK_U_V8, ServerKeyService.aad("u42", 1))
    }

    private fun body(userId: String = "u42", alg: String, version: Int? = null) =
        if (version == null) """{"userId":"$userId","alg":"$alg"}"""
        else """{"userId":"$userId","version":$version,"alg":"$alg"}"""

    private companion object {
        const val PATH = "/internal/keys/derive"
    }
}
