package de.trustylynx

// Alle Secrets kommen aus Umgebungsvariablen (.env lokal / env_file im Container)
object Secrets {
    private fun env(name: String): String =
        System.getenv(name) ?: error("Umgebungsvariable $name fehlt")

    private fun envHex32(name: String): ByteArray {
        val bytes = env(name).hexToByteArray()   // "7a11…" (64 Zeichen) → 32 Byte
        require(bytes.size == 32) { "$name muss 64 Hex-Zeichen (32 Byte) haben" }
        return bytes
    }

    val authServiceToken = env("AUTH_SERVICE_TOKEN")
    val vaultServiceToken = env("VAULT_SERVICE_TOKEN")

    val pepperLogin: ByteArray = envHex32("TEST_PEPPER_LOGIN")
    val pepperVault: ByteArray = envHex32("TEST_PEPPER_VAULT")

    val msk: ByteArray = envHex32("MSK")
}