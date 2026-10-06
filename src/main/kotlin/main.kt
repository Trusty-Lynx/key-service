package de.trustylynx

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)

}

// Alle Secrets kommen aus Umgebungsvariablen (.env lokal / env_file im Container)
object Secrets {
    private fun env(name: String): String =
        System.getenv(name) ?: error("Umgebungsvariable $name fehlt")

    val authServiceToken = env("AUTH_SERVICE_TOKEN")
    val vaultServiceToken = env("VAULT_SERVICE_TOKEN")

    val pepperLogin: ByteArray = env("TEST_PEPPER_LOGIN").toByteArray(Charsets.UTF_8)
    val pepperVault: ByteArray = env("TEST_PEPPER_VAULT").toByteArray(Charsets.UTF_8)

    val msk: ByteArray = env("MSK").toByteArray(Charsets.UTF_8)
}