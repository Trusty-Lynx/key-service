package de.trustylynx

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import kotlin.test.Test
import kotlin.test.assertEquals

class HealthRouteTest {

    @Test
    fun `health returns ok without a token while the database is reachable`() = withApp { client ->
        val response = client.get("/health")

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("""{"status":"ok"}""", response.bodyAsText())
    }

    @Test
    fun `health returns 503 when the database is not reachable`() = withApp(healthy = false) { client ->
        val response = client.get("/health")

        assertEquals(HttpStatusCode.ServiceUnavailable, response.status)
        assertEquals("""{"status":"unavailable"}""", response.bodyAsText())
    }
}
