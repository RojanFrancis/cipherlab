package com.rojan.cipherlab.crypto.mitm;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.rojan.cipherlab.common.InvalidRequestException;

/**
 * Controlled MITM simulation — Experiment A of the spec, performed entirely
 * against local toy values. <b>This never touches a network socket and never
 * operates on real sessions</b> (spec §7: "a deliberately simulated lab, not
 * an endpoint that attacks real users or networks").
 *
 * <p>Scenario, using small DH-style numbers with 3 participants:
 *
 * <pre>
 * UNAUTHENTICATED MODE (key substitution succeeds)
 *   Alice ──A = g^a──▶ Mallory swaps in A' = g^m ──▶ Bob trusts A'
 *   Bob   ──B = g^b──▶ Mallory swaps in B' = g^n ──▶ Alice trusts B'
 *   ⇒ Alice shares s_am with Mallory; Bob shares s_bm with Mallory;
 *     Alice believes she talks to Bob. Mallory reads everything.
 *
 * AUTHENTICATED MODE (signatures over the transcript)
 *   Public values arrive signed by the identity key of the claimed sender.
 *   Mallory cannot produce Alice's signature on A' ⇒ substitution flag trips
 *   before any message is ever encrypted.
 * </pre>
 */
@Component
public class MitmSimulation {

    public static final String UNAUTHENTICATED = "unauthenticated";
    public static final String AUTHENTICATED = "authenticated";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger P = BigInteger.valueOf(23);   // toy prime
    private static final BigInteger G = BigInteger.valueOf(5);

    /**
     * @param mode {@code unauthenticated} or {@code authenticated}
     * @return narrative + per-party shared secrets + detection flags
     */
    public Simulation simulate(String mode) {
        if (!UNAUTHENTICATED.equals(mode) && !AUTHENTICATED.equals(mode)) {
            throw new InvalidRequestException("INVALID_MODE", "mode must be unauthenticated or authenticated");
        }
        boolean unauthenticated = UNAUTHENTICATED.equals(mode);

        // Deterministic-ish fresh private values (1 < x < 22 for p = 23)
        int a = 2 + RANDOM.nextInt(18);  // Alice
        int b = 2 + RANDOM.nextInt(18);  // Bob
        int m = 2 + RANDOM.nextInt(18);  // Mallory (her two ephemeral keys)
        int n = 2 + RANDOM.nextInt(18);

        BigInteger aliceReal = G.modPow(BigInteger.valueOf(a), P);   // A
        BigInteger bobReal = G.modPow(BigInteger.valueOf(b), P);     // B
        BigInteger malloryA = G.modPow(BigInteger.valueOf(m), P);    // A' sent to Bob
        BigInteger malloryB = G.modPow(BigInteger.valueOf(n), P);    // B' sent to Alice

        Map<String, String> secrets = new LinkedHashMap<>();
        List<String> steps;
        boolean malloryCanRead;
        boolean substitutionDetected;

        if (unauthenticated) {
            BigInteger aliceSeesMallory = malloryB.modPow(BigInteger.valueOf(a), P); // s(Alice,Mallory)
            BigInteger bobSeesMallory = malloryA.modPow(BigInteger.valueOf(b), P);   // s(Bob,Mallory)
            BigInteger malloryWithAlice = aliceReal.modPow(BigInteger.valueOf(n), P);
            BigInteger malloryWithBob = bobReal.modPow(BigInteger.valueOf(m), P);
            // Mallory's two ends must agree with her counterparts:
            if (!aliceSeesMallory.equals(malloryWithAlice) || !bobSeesMallory.equals(malloryWithBob)) {
                throw new IllegalStateException("simulation invariant violated");
            }
            secrets.put("alice ↔ mallory", aliceSeesMallory.toString());
            secrets.put("bob ↔ mallory", bobSeesMallory.toString());
            secrets.put("alice ↔ bob (intended)", "no shared secret exists");
            malloryCanRead = true;
            substitutionDetected = false;
            steps = List.of(
                    "1. Alice publishes A = g^" + a + " mod 23 = " + aliceReal + " (she means it for Bob)",
                    "2. Mallory intercepts, keeps A, and sends A' = g^" + m + " mod 23 = " + malloryA + " to Bob",
                    "3. Bob accepts A' — nothing binds A' to Alice's identity",
                    "4. Bob publishes B; Mallory swaps in B' = g^" + n + " mod 23 = " + malloryB + " for Alice",
                    "5. Alice derives s = (B')^" + a + " mod 23 = " + aliceSeesMallory
                            + " — she thinks it's Bob's",
                    "6. Bob derives s = (A')^" + b + " mod 23 = " + bobSeesMallory
                            + " — he thinks it's Alice's",
                    "7. Both 'shared secrets' terminate at Mallory: she decrypts Alice's traffic with step 5's "
                            + "value, re-encrypts, and forwards to Bob with step 6's value",
                    "8. RESULT: undetectable man-in-the-middle — math agreed perfectly, "
                            + "and that is exactly the problem");
        } else {
            // Authenticated: public values carry signatures from the claimed sender's
            // identity key. Mallory can re-encrypt (sign with her own key) — but the
            // verifier checks against ALICE's registered public key, so it fails.
            BigInteger aliceSeesMallory = malloryB.modPow(BigInteger.valueOf(a), P);
            BigInteger bobTrustedAlice = aliceReal.modPow(BigInteger.valueOf(b), P); // no substitution happened
            secrets.put("alice ↔ bob", bobTrustedAlice.toString() + " (authenticated)");
            secrets.put("alice ↔ mallory", "no — substitution rejected before derivation");
            secrets.put("bob ↔ mallory", "no — substitution rejected before derivation");
            malloryCanRead = false;
            substitutionDetected = true;
            steps = List.of(
                    "1. Alice publishes A = " + aliceReal + " together with ECDSA(AliceIdentityKey, transcript) — "
                            + "her signature over (A, recipient-hint)",
                    "2. Mallory intercepts and substitutes A' = " + malloryA,
                    "3. Bob verifies the attached signature against Alice's registered public key",
                    "4. Signature verification FAILS — Mallory only holds her own private key, "
                            + "and a database entry does not let her forge identities she doesn't own",
                    "5. Bob aborts the handshake (substitutionDetected = true). No session key, "
                            + "no message, no ciphertext exists to attack",
                    "6. Same result in the other direction: Alice rejects Mallory's B' just as fast",
                    "7. RESULT: the identical attack that succeeded without authentication now fails "
                            + "— the only difference is binding identities to ephemeral keys with signatures");
        }

        return new Simulation(
                mode,
                List.of("alice", "mallory", "bob"),
                secrets,
                malloryCanRead,
                substitutionDetected,
                steps,
                "Lab simulation on toy values only. Real deployments run exactly this logic but with "
                        + "P-256 ECDH + identity signatures (see the secure channel architecture).");
    }

    public record Simulation(
            String mode,
            List<String> participants,
            Map<String, String> sharedSecrets,
            Boolean malloryCanRead,
            Boolean substitutionDetected,
            List<String> steps,
            String securityNote) {}
}