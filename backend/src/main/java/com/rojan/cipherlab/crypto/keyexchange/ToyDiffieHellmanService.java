package com.rojan.cipherlab.crypto.keyexchange;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Component;

import com.rojan.cipherlab.common.InvalidRequestException;

/**
 * Toy Diffie–Hellman key agreement — the classroom arithmetic behind
 * every modern key exchange, including the ECDH used in the secure channel.
 *
 * <h2>The math (and nothing more)</h2>
 * <pre>
 *   Public:  prime p, generator g
 *   Private: a (Alice), b (Bob)
 *   A = g^a mod p          B = g^b mod p
 *   Alice: s = B^a mod p   Bob: s = A^b mod p      → both equal g^(ab) mod p
 * </pre>
 *
 * <h2>Why outputs are mathematically equal but cryptographically unsafe</h2>
 * Raw DH gives both parties the same number — and <em>so does an attacker
 * who intercepts the exchange</em>. Without authenticating A and B, Mallory
 * can run one DH with Alice and another with Bob and read everything
 * (the MITM experiment). Real systems add: signatures over the transcript
 * (authenticated key exchange), HKDF (turn the raw secret into keys), and
 * ephemeral values (forward secrecy).
 *
 * <h2>DoS bounds (spec §5)</h2>
 * This endpoint performs modular exponentiation <em>in response to user
 * input</em>, so inputs are tightly bounded: {@code p} ≤ 512 bits,
 * exponents ∈ [1, p−2], {@code 2 ≤ g < p}. No unbounded {@code modPow}.
 *
 * <p>Keys produced here are <b>toy values</b> and are structurally prevented
 * from reaching the messaging module (separate classes, separate DTOs).
 */
@Component
public class ToyDiffieHellmanService {

    /** Classroom example: smallest safe prime where the standard worked example lives. */
    public static final BigInteger TEXTBOOK_P = BigInteger.valueOf(23);
    public static final BigInteger TEXTBOOK_G = BigInteger.valueOf(5);

    /** Largest prime accepted from the API — protects against CPU exhaustion. */
    public static final int MAX_P_BITS = 512;

    /** Complete toy exchange with human-readable calculation steps. */
    public record DhExchange(
            String p,
            String g,
            String alicePrivate,
            String bobPrivate,
            String alicePublic,
            String bobPublic,
            String aliceShared,
            String bobShared,
            String sharedSecret,
            List<String> steps) {}

    /**
     * Runs one toy exchange.
     *
     * @throws InvalidRequestException {@code INVALID_DH_PARAMETERS} when any
     *         input falls outside the bounded educational configuration
     */
    public DhExchange exchange(String pStr, String gStr, String alicePrivateStr, String bobPrivateStr) {
        BigInteger p = parse("p", pStr);
        BigInteger g = parse("g", gStr);
        BigInteger a = parse("alicePrivate", alicePrivateStr);
        BigInteger b = parse("bobPrivate", bobPrivateStr);

        if (p.bitLength() > MAX_P_BITS || p.compareTo(BigInteger.TWO) <= 0) {
            throw new InvalidRequestException("INVALID_DH_PARAMETERS",
                    "p must be a prime between 3 and 2^" + MAX_P_BITS + " (lab bound)");
        }
        if (g.compareTo(BigInteger.TWO) < 0 || g.compareTo(p) >= 0) {
            throw new InvalidRequestException("INVALID_DH_PARAMETERS",
                    "g must satisfy 2 <= g < p");
        }
        if (a.signum() <= 0 || a.compareTo(p.subtract(BigInteger.ONE)) >= 0
                || b.signum() <= 0 || b.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            throw new InvalidRequestException("INVALID_DH_PARAMETERS",
                    "private exponents must satisfy 1 < x < p-1");
        }

        BigInteger alicePublic = g.modPow(a, p);   // A = g^a mod p
        BigInteger bobPublic = g.modPow(b, p);     // B = g^b mod p
        BigInteger aliceShared = bobPublic.modPow(a, p); // s = B^a mod p
        BigInteger bobShared = alicePublic.modPow(b, p); // s = A^b mod p

        if (!aliceShared.equals(bobShared)) {
            throw new IllegalStateException("DH invariant violated: shared secrets must agree");
        }

        List<String> steps = List.of(
                "1. Public parameters: p = " + p + ", g = " + g,
                "2. Alice picks private a = " + a + " and publishes A = g^a mod p = " + alicePublic,
                "3. Bob picks private b = " + b + " and publishes B = g^b mod p = " + bobPublic,
                "4. Alice computes s = B^a mod p = " + aliceShared,
                "5. Bob computes s = A^b mod p = " + bobShared,
                "6. Both arrive at s = " + aliceShared + " ... but so could an interceptor!",
                "7. Math agreement ≠ authenticated exchange: without signatures on A and B, "
                        + "this same handshake is MITM-able (see the MITM experiment). "
                        + "Production systems also run the result through HKDF before using it as a key.");

        return new DhExchange(
                p.toString(), g.toString(),
                a.toString(), b.toString(),
                alicePublic.toString(), bobPublic.toString(),
                aliceShared.toString(), bobShared.toString(),
                aliceShared.toString(),
                steps);
    }

    private static BigInteger parse(String field, String value) {
        try {
            return new BigInteger(value);
        } catch (NumberFormatException e) {
            // Silence digit-length probes: report a generic bound violation.
            throw new InvalidRequestException("INVALID_DH_PARAMETERS",
                    field + " must be a positive decimal integer within lab bounds");
        }
    }
}