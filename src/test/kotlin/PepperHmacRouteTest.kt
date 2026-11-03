package de.trustylynx

import de.trustylynx.security.LOGIN_KEY_V0
import io.ktor.http.HttpStatusCode
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlinx.serialization.json.jsonPrimitive

// POST /internal/pepper-hmac, documentation/api/key-service/pepper-hmac.md
class PepperHmacRouteTest {

    @Test
    fun `auth service with login returns 200 and HMAC with pepper_login`() = withApp { client ->
        val response = client.postJson(PATH, body("login", b64(KEY)), AUTH_TOKEN)

        assertEquals(HttpStatusCode.OK, response.status)
        val h = unb64(response.json()["h"]!!.jsonPrimitive.content)
        assertContentEquals(hmac(PEPPER_LOGIN.toByteArray(), KEY), h)
    }

    @Test
    fun `vault service with vault returns 200 and HMAC with pepper_vault`() = withApp { client ->
        val response = client.postJson(PATH, body("vault", b64(KEY)), VAULT_TOKEN)

        assertEquals(HttpStatusCode.OK, response.status)
        val h = unb64(response.json()["h"]!!.jsonPrimitive.content)
        assertContentEquals(hmac(PEPPER_VAULT.toByteArray(), KEY), h)
    }

    @Test
    fun `missing token returns 401`() = withApp { client ->
        val response = client.postJson(PATH, body("login", b64(KEY)), token = null)

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("unauthorized", response.errorCode())
    }

    @Test
    fun `unknown token returns 401`() = withApp { client ->
        val response = client.postJson(PATH, body("login", b64(KEY)), "wrong-token")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("unauthorized", response.errorCode())
    }

    @Test
    fun `auth service asking for vault returns 403`() = withApp { client ->
        val response = client.postJson(PATH, body("vault", b64(KEY)), AUTH_TOKEN)

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals("forbidden", response.errorCode())
    }

    @Test
    fun `vault service asking for login returns 403`() = withApp { client ->
        val response = client.postJson(PATH, body("login", b64(KEY)), VAULT_TOKEN)

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals("forbidden", response.errorCode())
    }

    @Test
    fun `unknown purpose returns 400`() = withApp { client ->
        val response = client.postJson(PATH, body("foo", b64(KEY)), AUTH_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    @Test
    fun `key not base64 returns 400`() = withApp { client ->
        val response = client.postJson(PATH, body("login", "not base64!"), AUTH_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    @Test
    fun `key with 31 bytes returns 400`() = withApp { client ->
        val response = client.postJson(PATH, body("login", b64(ByteArray(31))), AUTH_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    @Test
    fun `malformed json returns 400`() = withApp { client ->
        val response = client.postJson(PATH, """{"purpose":""", AUTH_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    @Test
    fun `missing field returns 400`() = withApp { client ->
        val response = client.postJson(PATH, """{"purpose":"login","userId":"u42"}""", AUTH_TOKEN)

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("bad_request", response.errorCode())
    }

    private fun body(purpose: String, key: String) =
        """{"purpose":"$purpose","userId":"u42","key":"$key"}"""

    // calculated without pepperHmac() on purpose
    private fun hmac(pepper: ByteArray, key: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(pepper, "HmacSHA256")) }.doFinal(key)

    private companion object {
        const val PATH = "/internal/pepper-hmac"
        val KEY = LOGIN_KEY_V0
    }
}
