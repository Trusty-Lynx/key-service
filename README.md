# key-service

Verwaltet die Serverschlüssel der Nutzer und die beiden Pepper: legt Schlüssel an, leitet daraus die Teilschlüssel für die Crypto-Services ab und rechnet den Pepper-HMAC für Login und Tresor.
Passwörter, Sessions und Tresordaten kennt dieser Service nicht.

Kotlin 2.4 · Ktor 3.6 · PostgreSQL 17 · Java 21

## Endpoints

| Methode | Pfad | Zweck | Wer darf das aufrufen? |
|---|---|---|---|
| `GET` | `/health` | `200`, wenn Service und Datenbank laufen, sonst `503` | alle, ohne Token |
| `POST` | `/internal/pepper-hmac` | `HMAC-SHA256(pepper, key)` für einen `purpose` | Auth-Service mit `login`, Vault-Service mit `vault` |
| `POST` | `/internal/users/create` | Serverschlüssel `SDK_u` für einen neuen Nutzer würfeln und mit dem MSK verpackt speichern, antwortet `201` | nur Auth-Service |
| `POST` | `/internal/keys/derive` | Teilschlüssel für einen Nutzer ableiten, ohne `version` aus dem aktiven Schlüssel | Crypto 1 mit `aes`, Crypto 2 mit `chacha` |

Die `/internal/…`-Endpoints erkennen den Aufrufer am Header `X-Service-Token`. Fehlt der Token oder gehört er nicht zu diesem Endpoint, kommt `401`.
Gültig, aber nicht berechtigt ergibt `403`: ein fremder `purpose` oder `alg`, bei `/internal/users/create` auch der Token jedes anderen Service.
Der Token wird immer vor dem Body geprüft.

## Struktur

```text
src/main/kotlin/
├── Application.kt   Start: liest die Konfiguration, baut alle Teile, verbindet sie
├── AppConfig.kt     alle Umgebungsvariablen an einer Stelle
├── routes/          HTTP: Request lesen, Token und Eingaben prüfen, Service aufrufen, antworten
├── services/        Fachlogik (ServerKeyService: Schlüssel anlegen und ableiten)
├── repositories/    SQL mit JDBC, Datenbank-Setup
├── models/          Requests/Responses, Tabellenzeile, Fehlerklassen
├── security/        HKDF, Pepper-HMAC, Schlüssel ein- und auspacken (AES-256-GCM)
└── plugins/         Ktor-Einrichtung: JSON, Fehlerantworten
```

Ein Request läuft immer `routes` → `services` → `repositories`. Nur der Pepper-HMAC braucht keinen Service und rechnet direkt in der Route.
Fehler werden als Exception geworfen (`models/ApiException.kt`) und zentral in `plugins/StatusPages.kt` beantwortet.
Das Interface `ServerKeyRepository` gibt es, damit die Tests ohne Datenbank laufen.

Alle Services sollen so aufgebaut sein. Die Anleitung steht im `auth-service` in `SERVICE-STRUKTUR.md`.

## Lokal starten

```bash
docker compose -f docker-compose.dev.yml up -d   # Postgres auf localhost:5433
cp -n .env.example .env                          # Werte eintragen
set -a; source .env; set +a
./gradlew run                                    # Port 8080
```

Alle Variablen aus `.env.example` sind Pflicht, sonst startet der Service nicht. Nur mit `-Dio.ktor.development=true` haben die `DB_`-Variablen Dev-Defaults, die Tokens, Pepper und der MSK bleiben auch dann Pflicht.

Die Tabelle legt der Service nicht selbst an (siehe „Offen“). Für eine leere Datenbank reicht das hier, abgeleitet aus dem SQL im Code und der Doku:

```sql
CREATE TABLE server_keys (
  user_id     TEXT    NOT NULL,
  version     INTEGER NOT NULL,
  wrapped_sdk BYTEA   NOT NULL,
  active      BOOLEAN NOT NULL,
  PRIMARY KEY (user_id, version)
);
```

## Tests

```bash
./gradlew test
```

Die Endpoint-Tests laufen ohne Datenbank, `InMemoryServerKeyRepository` in `src/test/kotlin/TestSupport.kt` ersetzt sie. Die festen Tokens und Pepper dafür setzt `tasks.test` in `build.gradle.kts`.
`ResponseContractTest` hält die Antworten Byte für Byte fest, inklusive `"reason":null` und der Prüfreihenfolge. `security/SecurityTest.kt` prüft die Testvektoren aus dem Krypto-Handbuch.
Docker wird für die Tests nicht gebraucht, es wird nichts übersprungen.

## Deploy

Ein Push auf den Branch `deploy` kopiert die Dateien per `rsync` auf den Server, baut dort das Image und startet es neu (`.github/workflows/deploy.yml`).
Die `.env` liegt nur auf dem Server. Der Container hört auf Port `8080`, nach außen ist das Port `7492`.

## Offen

- **Schema:** Der Service legt `server_keys` nicht selbst an, im Repo gibt es weder Flyway noch SQL. Auf einer leeren Datenbank schlägt jeder Zugriff auf die Tabelle fehl. Auch das SQL im Code deckt kein automatischer Test ab.
- **Doku und Code:** `create-user-keys.md` beschreibt `POST /internal/users/{userId}/keys` ohne Body und `version` als Zahl. Der Code hat `POST /internal/users/create` mit Body und antwortet `{"version":"1"}` als String. Die Doku zeigt Fehler außerdem ohne `reason`, geschickt wird `"reason":null`.
- **MSK:** Die Doku nennt ein Docker Secret unter `/run/secrets/msk`, der Code liest die Umgebungsvariable `MSK`.
- **Format von Pepper und MSK:** Der Wert wird als Text genommen und nicht dekodiert. Ein Hex-String mit 64 Zeichen lässt den Start scheitern, zufällige 32 Byte lassen sich so nicht angeben. Mit `openssl rand -hex 16` sind es nur 128 Bit Zufall in 32 Byte.
- **Name `TEST_PEPPER_*`:** Der Name klingt nach Testwerten, der Server liest aber genau diese Variablen.
- **Eingaben:** `userId` ist bei `/internal/pepper-hmac` Pflicht, wird aber nicht benutzt und darf leer sein. Eine Längenbegrenzung für `userId` gibt es nirgends. `json()` ist locker eingestellt, `{purpose:login}` ohne Anführungszeichen wird also angenommen.
- **Erreichbarkeit:** `docker-compose.yml` veröffentlicht Port `7492`, die `/internal/…`-Endpoints schützt dann nur der Token.
- **`Dockerfile`:** `EXPOSE 7491` passt nicht zum Port `8080`, auf dem der Service wirklich hört.
- **Fehlende Endpoints:** Es gibt keinen Weg, die Schlüssel eines Nutzers zu löschen (Crypto-Shredding) oder zu rotieren.
- **Abhängigkeiten:** `ktor-client-cio`, `ktor-client-content-negotiation` und `bouncycastle` stehen in `build.gradle.kts`, werden aber nicht benutzt.
- **`Secrets`:** Tokens, Pepper und MSK liegen im globalen Objekt `Secrets`, nicht wie im `auth-service` in `AppConfig`. So bleiben die Tests beim Umbau unverändert. Umstellen braucht eine Zeile in `TestSupport.kt`.
