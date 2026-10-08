package de.trustylynx

import de.trustylynx.domain.ServerKeyService
import de.trustylynx.security.hkdf
import de.trustylynx.security.pepperHmac
import de.trustylynx.security.unwrapKey
import de.trustylynx.security.wrapKey
import javax.crypto.AEADBadTagException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

// Testvektoren aus documentation/grundgerüst/Verschlüsselung.md, Abschnitt 8
class SecurityTest {

    @Test
    fun `V0 pepperHmac matches h_login`() {
        val h = pepperHmac(PEPPER_LOGIN_V0, LOGIN_KEY_V0)
        assertContentEquals(hex("3054ff7d44be22a77e1ecb2dbe2d4e90eeb0010bd0a964369ff32f20d82d1608"), h)
    }

    @Test
    fun `V8 hkdf aes matches K_aes`() {
        assertContentEquals(K_AES_V8, hkdf(SDK_U_V8, "TL-L2-aes"))
    }

    @Test
    fun `V8 hkdf chacha matches K_chacha`() {
        assertContentEquals(K_CHACHA_V8, hkdf(SDK_U_V8, "TL-L2-chacha"))
    }

    @Test
    fun `V7 wrap then unwrap returns SDK_u`() {
        val aad = ServerKeyService.aad("u42", 1)
        val wrapped = wrapKey(TEST_MSK, SDK_U_V8, aad)

        assertEquals(60, wrapped.size)   // 12 Nonce + 32 Key + 16 Tag
        assertContentEquals(SDK_U_V8, unwrapKey(TEST_MSK, wrapped, aad))
    }

    @Test
    fun `V7 unwrap with other userId fails`() {
        val wrapped = wrapKey(TEST_MSK, SDK_U_V8, ServerKeyService.aad("u42", 1))

        assertFailsWith<AEADBadTagException> { unwrapKey(TEST_MSK, wrapped, ServerKeyService.aad("u43", 1)) }
    }

    @Test
    fun `V7 unwrap with other version fails`() {
        val wrapped = wrapKey(TEST_MSK, SDK_U_V8, ServerKeyService.aad("u42", 1))

        assertFailsWith<AEADBadTagException> { unwrapKey(TEST_MSK, wrapped, ServerKeyService.aad("u42", 2)) }
    }

    @Test
    fun `V7 unwrap with other MSK fails`() {
        val aad = ServerKeyService.aad("u42", 1)
        val wrapped = wrapKey(TEST_MSK, SDK_U_V8, aad)

        assertFailsWith<AEADBadTagException> { unwrapKey(ByteArray(32) { 1 }, wrapped, aad) }
    }

    @Test
    fun `V7 unwrap of tampered data fails`() {
        val aad = ServerKeyService.aad("u42", 1)
        val wrapped = wrapKey(TEST_MSK, SDK_U_V8, aad)
        wrapped[20] = (wrapped[20].toInt() xor 1).toByte()

        assertFailsWith<AEADBadTagException> { unwrapKey(TEST_MSK, wrapped, aad) }
    }

    @Test
    fun `V7 unwrap with wrong length fails`() {
        val aad = ServerKeyService.aad("u42", 1)
        val wrapped = wrapKey(TEST_MSK, SDK_U_V8, aad)

        assertFailsWith<AEADBadTagException> { unwrapKey(TEST_MSK, wrapped.copyOf(59), aad) }
    }
}

val PEPPER_LOGIN_V0 = hex("7a117269da84a2b92f7a6e818a5fbd5960ab53e59d6516b8be8580bf34536b92")
val LOGIN_KEY_V0 = hex("d478c17d852a24d1f26dc3c1590a3289eb10b4e163d0653412776667a2495377")
val SDK_U_V8 = hex("87c8b55eb8ffbd6ba864ead1ff91327b931e8718e0a4197213207ddd539ec6b1")
val K_AES_V8 = hex("ef2aaabcd310f69808a4283bea9b2b21c12ff90b14893b200f85d3b84e1eb4a6")
val K_CHACHA_V8 = hex("d904d3354ad5958cd4c714ef5cb5ca727b48614cab801010737ca5f91485641f")
