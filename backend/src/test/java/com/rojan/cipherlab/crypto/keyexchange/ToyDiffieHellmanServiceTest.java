package com.rojan.cipherlab.crypto.keyexchange;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.rojan.cipherlab.common.InvalidRequestException;

/**
 * Textbook Diffie–Hellman: p = 23, g = 5, a = 6, b = 15.
 *
 * <pre>
 *   A = 5^6  mod 23 = 8        s = 19^6 mod 23 = 2
 *   B = 5^15 mod 23 = 19       s = 8^15  mod 23 = 2
 * </pre>
 */
class ToyDiffieHellmanServiceTest {

    private final ToyDiffieHellmanService dh = new ToyDiffieHellmanService();

    @Test
    @DisplayName("both parties derive the same shared secret (spec minimum test)")
    void sharedSecretAgreement() {
        var x = dh.exchange("23", "5", "6", "15");

        assertEquals("8", x.alicePublic(), "A = g^a mod p");
        assertEquals("19", x.bobPublic(), "B = g^b mod p");
        assertEquals("2", x.aliceShared());
        assertEquals("2", x.bobShared());
        assertEquals(x.aliceShared(), x.sharedSecret());
        assertEquals(x.aliceShared(), x.bobShared(), "agreement invariant");
        assertTrue(x.steps().size() >= 5, "each exchange must expose its calculation steps");
        assertTrue(x.steps().get(x.steps().size() - 1).contains("MITM"),
                "final step must flag that math agreement ≠ authenticated exchange");
    }

    @Test
    @DisplayName("agreement also holds for larger bounded primes")
    void largerBoundedPrime() {
        // RFC 3526 1024-bit group is under the 512-bit bound? No — use a 256-bit prime.
        String p = "115792089237316195423570985008687907853269984665640564039457584007913129639747"; // 2^255 - 19 (prime)
        String g = "2";
        var x = dh.exchange(p, g, "12345", "67890");
        assertEquals(x.aliceShared(), x.bobShared());
        assertEquals(new BigInteger(g).modPow(new BigInteger("12345"), new BigInteger(p)),
                new BigInteger(x.alicePublic()));
    }

    @Test
    @DisplayName("oversized p is rejected — CPU-exhaustion bound (spec §5)")
    void oversizedPrimeRejected() {
        // 600-bit decimal string > 512 bits
        String p = "2".repeat(181); // ~600 bits
        InvalidRequestException ex = assertThrows(InvalidRequestException.class,
                () -> dh.exchange(p, "5", "6", "15"));
        assertEquals("INVALID_DH_PARAMETERS", ex.getCode());
    }

    @Test
    @DisplayName("exponent outside 1 < x < p-1 is rejected")
    void exponentBoundsEnforced() {
        assertThrows(InvalidRequestException.class, () -> dh.exchange("23", "5", "0", "15"));
        assertThrows(InvalidRequestException.class, () -> dh.exchange("23", "5", "6", "23"));
        assertThrows(InvalidRequestException.class, () -> dh.exchange("23", "5", "-4", "15"));
    }

    @Test
    @DisplayName("g outside [2, p) is rejected")
    void generatorBoundsEnforced() {
        assertThrows(InvalidRequestException.class, () -> dh.exchange("23", "1", "6", "15"));
        assertThrows(InvalidRequestException.class, () -> dh.exchange("23", "30", "6", "15"));
    }

    @Test
    @DisplayName("non-decimal or oversized numeric input is rejected generically")
    void malformedNumbersRejected() {
        InvalidRequestException ex = assertThrows(InvalidRequestException.class,
                () -> dh.exchange("abc", "5", "6", "15"));
        assertEquals("INVALID_DH_PARAMETERS", ex.getCode(),
                "malformed input must not leak parser internals");
        assertThrows(InvalidRequestException.class,
                () -> dh.exchange("9".repeat(161), "5", "6", "15"));
    }
}