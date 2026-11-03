package de.trustylynx

import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// POST /internal/users/create, documentation/api/key-service/create-user-keys.md
class NewUserRouteTest {

    @Test
    fun `auth service creates keys and gets 201 with version 1`() {
        val repo = InMemoryServerKeyRepository()
        withApp(repo) { client ->
            val response = client.postJson(PATH, body("u42"), AUTH_TOKEN)

            assertEquals(HttpStatusCode.Created, response.status)
            assertEquals("1", response.json()["version"]!!.jsonPrimitive.content)
            assertEquals(60, repo.rows["u42" to 1]!!.size)   // wrapped_sdk, not SDK_u
        }
    }

    @Test
    fun `created keys can be derived afterwards`() = withApp { client ->
        assertEquals(HttpStatusCode.Created, client.postJson(PATH, body("u42"), AUTH_TOKEN).status)

        val response = client.postJson("/internal/keys/derive", """{"userId":"u42","alg":"aes"}""", AES_TOKEN)

        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `response does not contain SDK_u`() = withApp { client ->
        val response = client.postJson(PATH, body("u42"), AUTH_TOKEN)

        assertEquals(setOf("version"), response.json().keys)
    }

    @Test
    fun `second call for same user returns 409`() = withApp { client ->
        assertEquals(HttpStatusCode.Created, client.postJson(PATH, body("u42"), AUTH_TOKEN).status)

        val response = client.postJson(PATH, body("u42"), AUTH_TOKEN)

        assertEquals(HttpStatusCode.Conflict, response.status)
        assertEquals("already_exists", response.errorCode())
    }

    @Test
    fun `missing token returns 401`() = withApp { client ->
        val response = client.postJson(PATH, body("u42"), token = null)

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("unauthorized", response.errorCode())
    }

    @Test
    fun `unknown token returns 401`() = withApp { client ->
        val response = client.postJson(PATH, body("u42"), "wrong-token")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("unauthorized", response.errorCode())
    }

    @Test
    fun `vault service returns 403`() = withApp { client ->
        val response = client.postJson(PATH, body("u42"), VAULT_TOKEN)

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals("forbidden", response.errorCode())
    }

    @Test
    fun `crypto services return 403`() = withApp { client ->
        for (token in listOf(AES_TOKEN, CHACHA_TOKEN)) {
            val response = client.postJson(PATH, body("u42"), token)

            assertEquals(HttpStatusCode.Forbidden, response.status)
            assertEquals("forbidden", response.errorCode())
        }
    }

    @Test
    fun `forbidden caller does not create keys`() {
        val repo = InMemoryServerKeyRepository()
        withApp(repo) { client ->
            client.postJson(PATH, body("u42"), VAULT_TOKEN)

            assertTrue(repo.rows.isEmpty())
        }
    }

    @Test
    fun `blank userId returns 400`() = withApp { client ->
        val response = client.postJson(PATH, body("  "), AUTH_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    @Test
    fun `malformed json returns 400`() = withApp { client ->
        val response = client.postJson(PATH, """{"userId":""", AUTH_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    private fun body(userId: String) = """{"userId":"$userId"}"""

    private companion object {
        const val PATH = "/internal/users/create"
    }
}
