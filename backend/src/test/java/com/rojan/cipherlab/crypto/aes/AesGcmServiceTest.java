package com.rojan.cipherlab.crypto.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.rojan.cipherlab.common.AuthenticationFailedException;

/**
 * Spec §9 milestone tests:
 * <ol>
 *   <li>encrypt → decrypt returns the original plaintext;</li>
 *   <li>modified ciphertext is rejected (tag verification fails).</li>
 * </ol>
 * Extended to every other tamper surface GCM authenticates, because the
 * security claim we make in the repo is "authentication covers everything".
 */
class AesGcmServiceTest {

    private final AesGcmService aes = new AesGcmService();

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("encrypt then decrypt returns the exact original plaintext")
    void roundTripRecoversPlaintext() {
        byte[] key = aes.generateKey();
        byte[] plaintext = bytes("Attacks based on Diffie-Hellman are best prevented by authentication.");

        AesGcmService.EncryptedPayload p = aes.encrypt(key, plaintext, null);
        byte[] recovered = aes.decrypt(key, p.nonce(), p.ciphertext(), p.tag(), null);

        assertArrayEquals(plaintext, recovered, "roundtrip must be lossless");
        assertEquals(AesGcmService.KEY_BYTES, key.length);
        assertEquals(AesGcmService.NONCE_BYTES, p.nonce().length);
        assertEquals(AesGcmService.TAG_BYTES, p.tag().length);
        // Ciphertext must not leak the plaintext (best-effort sanity check).
        assertFalse(new String(p.ciphertext(), StandardCharsets.ISO_8859_1)
                .contains("Diffie"), "ciphertext must not contain plaintext fragments");
    }

    @Test
    @DisplayName("unicode plaintext survives the roundtrip")
    void roundTripUnicode() {
        byte[] key = aes.generateKey();
        byte[] plaintext = bytes("κρυπτογραφία 🔐 — 密码学");
        AesGcmService.EncryptedPayload p = aes.encrypt(key, plaintext, null);
        assertArrayEquals(plaintext, aes.decrypt(key, p.nonce(), p.ciphertext(), p.tag(), null));
    }

    @Test
    @DisplayName("empty plaintext still authenticates")
    void emptyPlaintext() {
        byte[] key = aes.generateKey();
        AesGcmService.EncryptedPayload p = aes.encrypt(key, new byte[0], null);
        assertEquals(0, p.ciphertext().length, "empty plaintext → zero-byte ciphertext");
        assertEquals(AesGcmService.TAG_BYTES, p.tag().length, "tag still present");
        assertEquals(0, aes.decrypt(key, p.nonce(), p.ciphertext(), p.tag(), null).length);
    }

    @Test
    @DisplayName("SPEC: flipping one bit of the ciphertext is rejected — no plaintext released")
    void tamperedCiphertextIsRejected() {
        byte[] key = aes.generateKey();
        byte[] secret = bytes("Project CipherLab stays secret until Friday");
        AesGcmService.EncryptedPayload p = aes.encrypt(key, secret, null);

        byte[] tampered = p.ciphertext().clone();
        tampered[3] ^= 0x01; // single-bit flip

        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class,
                () -> aes.decrypt(key, p.nonce(), tampered, p.tag(), null),
                "GCM must reject modified ciphertext");
        assertEquals(AuthenticationFailedException.DEFAULT_MESSAGE, ex.getMessage(),
                "error message must not leak plaintext or internals");
    }

    @Test
    @DisplayName("a single flipped tag bit is rejected")
    void tamperedTagIsRejected() {
        byte[] key = aes.generateKey();
        AesGcmService.EncryptedPayload p = aes.encrypt(key, bytes("integrity depends on this tag"), null);
        byte[] tag = p.tag().clone();
        tag[15] ^= (byte) 0x80;
        assertThrows(AuthenticationFailedException.class,
                () -> aes.decrypt(key, p.nonce(), p.ciphertext(), tag, null));
    }

    @Test
    @DisplayName("a flipped nonce bit fails decryption (wrong IV = authentication failure)")
    void tamperedNonceIsRejected() {
        byte[] key = aes.generateKey();
        AesGcmService.EncryptedPayload p = aes.encrypt(key, bytes("nonce binds the counter mode keystream"), null);
        byte[] nonce = p.nonce().clone();
        nonce[0] ^= 0x01;
        assertThrows(AuthenticationFailedException.class,
                () -> aes.decrypt(key, nonce, p.ciphertext(), p.tag(), null));
    }

    @Test
    @DisplayName("wrong key fails authentication even with all other inputs correct")
    void wrongKeyIsRejected() {
        AesGcmService.EncryptedPayload p = aes.encrypt(aes.generateKey(), bytes("keyed wrong"), null);
        byte[] wrongKey = aes.generateKey();
        assertThrows(AuthenticationFailedException.class,
                () -> aes.decrypt(wrongKey, p.nonce(), p.ciphertext(), p.tag(), null));
    }

    @Test
    @DisplayName("AAD mismatch is rejected — associated data is authenticated too")
    void aadMismatchIsRejected() {
        byte[] key = aes.generateKey();
        byte[] aad = bytes("conv=alice-bob seq=1");
        AesGcmService.EncryptedPayload p = aes.encrypt(key, bytes("session metadata is bound"), aad);
        assertDoesNotThrow(() -> aes.decrypt(key, p.nonce(), p.ciphertext(), p.tag(), aad),
                "matching AAD must decrypt");
        assertThrows(AuthenticationFailedException.class,
                () -> aes.decrypt(key, p.nonce(), p.ciphertext(), p.tag(), bytes("conv=mallory seq=9")),
                "swapped metadata must not authenticate");
    }

    @Test
    @DisplayName("fresh 96-bit nonce per encryption — never reused under one key")
    void noncesAreNeverRepeated() {
        byte[] key = aes.generateKey();
        String plaintext = "the same plaintext twice";
        var first = aes.encrypt(key, bytes(plaintext), null);
        var second = aes.encrypt(key, bytes(plaintext), null);

        assertFalse(Arrays.equals(first.nonce(), second.nonce()) && Arrays.equals(first.ciphertext(), second.ciphertext()),
                "identical plaintext under one key must produce distinct nonce AND ciphertext");
        String c1 = Base64.getEncoder().encodeToString(first.ciphertext());
        String c2 = Base64.getEncoder().encodeToString(second.ciphertext());
        assertFalse(c1.equals(c2), "GCM nonce reuse would leak XOR of plaintexts — must not happen");
    }

    @Test
    @DisplayName("key length is enforced — no silent AES-128 downgrade")
    void wrongKeyLengthRejected() {
        byte[] shortKey = new byte[16]; // legal AES-128 size, illegal here
        IllegalArgumentException enc = assertThrows(IllegalArgumentException.class,
                () -> aes.encrypt(shortKey, bytes("x"), null),
                "only 32-byte keys are allowed");
        assertTrue(enc.getMessage().contains("32 bytes"), "message must name the required key length");
        assertThrows(IllegalArgumentException.class,
                () -> aes.decrypt(shortKey, new byte[12], new byte[0], new byte[16], null));
    }
}