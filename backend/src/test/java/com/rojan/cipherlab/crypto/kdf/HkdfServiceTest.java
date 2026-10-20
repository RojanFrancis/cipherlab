package com.rojan.cipherlab.crypto.kdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.rojan.cipherlab.common.InvalidRequestException;

/**
 * RFC 5869 Appendix A, Test Case 1 (SHA-256):
 * <pre>
 * IKM  = 0x0b × 22
 * salt = 0x000102030405060708090a0b0c
 * info = 0xf0f1f2f3f4f5f6f7f8f9
 * L    = 42
 * PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
 * OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
 * </pre>
 */
class HkdfServiceTest {

    private final HkdfService hkdf = new HkdfService();

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    @Test
    @DisplayName("RFC 5869 test case 1: PRK and OKM match the published vectors exactly")
    void rfc5869TestCase1() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");

        var d = hkdf.derive(ikm, salt, info, 42);

        assertEquals("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                HkdfService.hex(d.prk()), "PRK vector");
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                HkdfService.hex(d.okm()), "OKM vector");
        assertEquals(42, d.okm().length);
    }

    @Test
    @DisplayName("different info ⇒ completely different key (context binding — the core lesson)")
    void infoBindsKeyToContext() {
        byte[] ikm = "shared-secret-from-dh".getBytes();
        String aliceToBob = HkdfService.hex(hkdf.derive(ikm, null, "CipherLab v1 Alice-Bob", 32).okm());
        String bobToAlice = HkdfService.hex(hkdf.derive(ikm, null, "CipherLab v1 Bob-Alice", 32).okm());
        String again = HkdfService.hex(hkdf.derive(ikm, null, "CipherLab v1 Alice-Bob", 32).okm());
        assertNotEquals(aliceToBob, bobToAlice, "distinct info must derive distinct keys");
        assertEquals(aliceToBob, again, "derivation must be deterministic");
    }

    @Test
    @DisplayName("different salt and different ikm also change the output")
    void saltAndIkmBinds() {
        byte[] ikm = "secret".getBytes();
        String base = HkdfService.hex(hkdf.derive(ikm, null, "ctx", 32).okm());
        String salted = HkdfService.hex(hkdf.derive(ikm, "pepper".getBytes(), "ctx", 32).okm());
        String otherIkm = HkdfService.hex(hkdf.derive("different".getBytes(), null, "ctx", 32).okm());
        assertNotEquals(base, salted, "salt must affect the key");
        assertNotEquals(base, otherIkm, "ikm must affect the key");
    }

    @Test
    @DisplayName("RFC output-length bounds: 0 and >8160 rejected; multi-block expansion works")
    void outputBoundsEnforced() {
        byte[] ikm = "x".getBytes();
        assertThrows(InvalidRequestException.class, () -> hkdf.derive(ikm, null, "ctx", 0));
        assertThrows(InvalidRequestException.class, () -> hkdf.derive(ikm, null, "ctx", 8161));
        assertThrows(InvalidRequestException.class, () -> hkdf.derive(new byte[0], null, "ctx", 32));
        assertEquals(64, hkdf.derive(ikm, null, "ctx", 64).okm().length, "two full blocks");
        assertEquals(33, hkdf.derive(ikm, null, "ctx", 33).okm().length, "partial second block");
    }

    @Test
    @DisplayName("steps narrate extract, expand, and the context lesson for the visualization")
    void stepsExplained() {
        var d = hkdf.derive("ikm".getBytes(), null, "demo", 32);
        String joined = String.join("\n", d.steps());
        assertTrue(joined.contains("EXTRACT"), "extract step present");
        assertTrue(joined.contains("EXPAND"), "expand step present");
        assertTrue(joined.contains("Different info"), "context lesson present");
        assertTrue(joined.contains("PRK  ="), "intermediate value exposed for the UI");
    }
}