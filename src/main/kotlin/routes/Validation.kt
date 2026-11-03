package de.trustylynx.routes

import de.trustylynx.Secrets
import de.trustylynx.models.BadRequest
import de.trustylynx.models.Forbidden
import de.trustylynx.models.Unauthorized
import io.ktor.server.application.ApplicationCall
import java.security.MessageDigest
import kotlin.io.encoding.Base64

private const val SERVICE_TOKEN_HEADER = "X-Service-Token"
private const val KEY_LENGTH = 32

// gives back the purpose of the calling service ("login" or "vault")
fun ApplicationCall.requirePurposeToken(): String {
    val token = request.headers[SERVICE_TOKEN_HEADER] ?: throw Unauthorized()
    return purposeForToken(token) ?: throw Unauthorized()
}

// only the auth service gets through. a valid token of another service is a 403, an unknown one a 401
fun ApplicationCall.requireAuthServiceToken() {
    val token = request.headers[SERVICE_TOKEN_HEADER] ?: throw Unauthorized()
    val purpose = purposeForToken(token)
    when {
        purpose == "login" -> return
        purpose != null || algForToken(token) != null -> throw Forbidden()
        else -> throw Unauthorized()
    }
}

// gives back the alg of the calling crypto service ("aes" or "chacha")
fun ApplicationCall.requireCryptoToken(): String {
    val token = request.headers[SERVICE_TOKEN_HEADER] ?: throw Unauthorized()
    return algForToken(token) ?: throw Unauthorized()
}

fun validatePurpose(tokenPurpose: String, requested: String) {
    if (requested != "login" && requested != "vault") throw BadRequest("unknown purpose")
    if (requested != tokenPurpose) throw Forbidden()
}

fun validateAlg(tokenAlg: String, requested: String) {
    if (requested != "aes" && requested != "chacha") throw BadRequest("unknown alg")
    if (requested != tokenAlg) throw Forbidden()
}

fun validateKey(base64Key: String): ByteArray {
    val key = try {
        Base64.decode(base64Key)
    } catch (_: IllegalArgumentException) {
        throw BadRequest("key is not base64")
    }
    if (key.size != KEY_LENGTH) throw BadRequest("key must be 32 bytes")
    return key
}

private fun purposeForToken(token: String): String? {
    val provided = token.toByteArray()
    // isEqual takes the same time wherever the bytes differ, so a token can't be guessed through timing
    return when {
        MessageDigest.isEqual(provided, Secrets.authServiceToken.toByteArray()) -> "login"
        MessageDigest.isEqual(provided, Secrets.vaultServiceToken.toByteArray()) -> "vault"
        else -> null
    }
}

// crypto 1 only gets K_aes, crypto 2 only K_chacha
private fun algForToken(token: String): String? {
    val provided = token.toByteArray()
    return when {
        MessageDigest.isEqual(provided, Secrets.aesServiceToken.toByteArray()) -> "aes"
        MessageDigest.isEqual(provided, Secrets.chachaServiceToken.toByteArray()) -> "chacha"
        else -> null
    }
}
