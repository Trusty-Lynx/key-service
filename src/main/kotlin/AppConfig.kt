package de.trustylynx

import de.trustylynx.repositories.DbConfig

class AppConfig(
    val db: DbConfig,
) {
    companion object {
        fun fromEnv() = AppConfig(
            db = DbConfig(
                url = envOrDev("DB_URL", "jdbc:postgresql://localhost:5433/keys"),
                user = envOrDev("DB_USER", "dev"),
                password = envOrDev("DB_PASSWORD", "dev"),
            ),
        )
    }
}

object Secrets {
    val authServiceToken = requireEnv("AUTH_SERVICE_TOKEN")
    val vaultServiceToken = requireEnv("VAULT_SERVICE_TOKEN")
    val aesServiceToken = requireEnv("AES_SERVICE_TOKEN")
    val chachaServiceToken = requireEnv("CHACHA_SERVICE_TOKEN")

    val pepperLogin: ByteArray = envBytes32("TEST_PEPPER_LOGIN")
    val pepperVault: ByteArray = envBytes32("TEST_PEPPER_VAULT")

    val msk: ByteArray = envBytes32("MSK")
}

private val isDevelopment = System.getProperty("io.ktor.development")?.toBoolean() == true

private fun requireEnv(name: String): String {
    val value = System.getenv(name)
    if (value.isNullOrBlank()) error("Missing required environment variable $name")
    return value
}

private fun envOrDev(name: String, devDefault: String): String {
    val value = System.getenv(name)
    if (!value.isNullOrBlank()) return value
    if (isDevelopment) return devDefault
    error("Missing required environment variable $name")
}

private fun envBytes32(name: String): ByteArray {
    // takes the text as it is, no hex or base64 decoding. a 64 character hex string fails here
    val bytes = requireEnv(name).toByteArray()
    require(bytes.size == 32) { "$name muss 32 Byte haben" }
    return bytes
}
