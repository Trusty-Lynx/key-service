package de.trustylynx.keyValidation

import de.trustylynx.Secrets
import java.security.MessageDigest

// Gibt zurück, für welchen purpose das Token gilt ("login" / "vault"), oder null wenn es zu keinem passt
fun purposeForToken(token: String): String? {
    val t = token.toByteArray()
    // isEqual vergleicht in konstanter Zeit, damit man das Token nicht über Timing erraten kann
    return when {
        MessageDigest.isEqual(t, Secrets.authServiceToken.toByteArray()) -> "login"
        MessageDigest.isEqual(t, Secrets.vaultServiceToken.toByteArray()) -> "vault"
        else -> null
    }
}
