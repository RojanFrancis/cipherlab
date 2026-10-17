package com.rojan.cipherlab.crypto.hashing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.rojan.cipherlab.common.InvalidRequestException;

/**
 * Known-answer tests against published vectors — if these fail, the
 * primitive is not SHA-2/HMAC and nothing downstream can be trusted.
 */
class HashingServiceTest {

    private final HashingService hashing = new HashingService();

    @Test
    @DisplayName("SHA-256('abc') matches the FIPS/NIST published digest")
    void sha256KnownVector() {
        assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                hashing.digest("abc", "SHA-256"));
    }

    @Test
    @DisplayName("SHA-512('abc') matches the published digest")
    void sha512KnownVector() {
        assertEquals(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                        + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                hashing.digest("abc", "SHA-512"));
    }

    @Test
    @DisplayName("one-bit input change flips most digest characters (avalanche effect)")
    void avalanche() {
        String d1 = hashing.digest("Mallory", "SHA-256");
        String d2 = hashing.digest("Mallory ", "SHA-256"); // single trailing space
        assertNotEquals(d1, d2, "different inputs must not collide");
        assertEquals(d1.length(), d2.length(), "digest length is fixed at 64 hex chars");
        long same = 0;
        for (int i = 0; i < d1.length(); i++) {
            if (d1.charAt(i) == d2.charAt(i)) same++;
        }
        // A ≈8-16 character matches would already be exceptional for random digests.
        assertTrue(same <= 24, "avalanche violated: digests share " + same + " positions");
    }

    @Test
    @DisplayName("HMAC-SHA-256 matches RFC 4231 test case 2 (key 'Jefe')")
    void hmacKnownVector() {
        assertEquals(
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                hashing.hmac("Jefe", "what do ya want for nothing?"));
    }

    @Test
    @DisplayName("HMAC changes when either the key OR the message changes")
    void hmacBindsKeyAndMessage() {
        String base = hashing.hmac("shared-secret", "transfer 100 to alice");
        assertNotEquals(base, hashing.hmac("shared-secrez", "transfer 100 to alice"),
                "different key must yield different MAC");
        assertNotEquals(base, hashing.hmac("shared-secret", "transfer 100 to mallory"),
                "different message must yield different MAC");
    }

    @Test
    @DisplayName("MD5/SHA-1 style algorithms are refused, not silently accepted")
    void algorithmWhitelist() {
        assertThrows(InvalidRequestException.class, () -> hashing.digest("x", "MD5"),
                "broken digests must be rejected");
        assertThrows(InvalidRequestException.class, () -> hashing.digest("x", "SHA-1"));
        InvalidRequestException ex = assertThrows(InvalidRequestException.class,
                () -> hashing.digest("x", "ROT13"));
        assertEquals("UNSUPPORTED_ALGORITHM", ex.getCode());
    }

    @Test
    @DisplayName("empty HMAC key is refused — a known misuse")
    void emptyHmacKeyRejected() {
        InvalidRequestException ex = assertThrows(InvalidRequestException.class,
                () -> hashing.hmac("", "data"));
        assertEquals("INVALID_KEY", ex.getCode());
    }
}