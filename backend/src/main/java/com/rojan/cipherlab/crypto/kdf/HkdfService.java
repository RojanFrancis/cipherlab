package com.rojan.cipherlab.crypto.kdf;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import com.rojan.cipherlab.common.InvalidRequestException;

import java.security.GeneralSecurityException;

/**
 * HKDF (RFC 5869) — HMAC-based Extract-and-Expand Key Derivation.
 *
 * <h2>Why a raw Diffie–Hellman secret must never become an AES key directly</h2>
 * The DH shared secret is a <em>uniformly random-looking number</em> but is
 * only computationally hard to guess — it lacks the exact bit distribution
 * and length a symmetric cipher expects, and it is reused across contexts.
 * HKDF:
 * <ol>
 *   <li><b>Extract</b> — squeezes an input key material that might be weak
 *       or high-entropy-but-biased into a uniformly random 256-bit PRK
 *       using a salt: {@code PRK = HMAC(salt, ikm)}.</li>
 *   <li><b>Expand</b> — stretches the PRK into any number of bytes bound to
 *       a context label {@code info}: different info ⇒ unrelated keys.</li>
 * </ol>
 * That label is what lets one handshake derive <em>two distinct directional
 * keys</em> ("client→server" vs "server→client") and why
 * {@code info="CipherLab v1 Alice-Bob"} never equals
 * {@code info="CipherLab v1 Bob-Alice"}.
 *
 * <p>Implemented from the RFC (two nested HMAC-SHA-256 constructions) rather
 * than {@code javax.crypto.SecretKeyFactory} so the lab can display each
 * intermediate value — production code should use a vetted library.
 */
@Component
public class HkdfService {

    public static final String ALGORITHM = "HmacSHA256";
    public static final int HASH_LEN = 32;   // SHA-256 output bytes
    public static final int MAX_OUTPUT = 255 * HASH_LEN; // RFC 5869 hard limit (8160)

    /** Full derivation with every intermediate value the UI will visualize. */
    public record Derivation(
            byte[] prk,      // Extract output
            byte[] okm,      // Expand output (the derived key material)
            List<String> steps) {}

    /**
     * @param ikm  input key material (e.g. the raw DH shared secret)
     * @param salt salt; {@code null}/empty becomes {@code HASH_LEN} zero
     *             bytes per RFC 5869 §2.2
     * @param info mandatory context label — different info ⇒ different keys
     * @param L    output length in bytes (1..8160)
     */
    public Derivation derive(byte[] ikm, byte[] salt, String info, int L) {
        byte[] infoBytes = (info == null) ? new byte[0] : info.getBytes(StandardCharsets.UTF_8);
        return derive(ikm, salt, infoBytes, (info == null) ? "" : info, L);
    }

    /** Byte-level entry point (String variant delegates here). */
    public Derivation derive(byte[] ikm, byte[] salt, byte[] infoBytes, int L) {
        return derive(ikm, salt, infoBytes, hex(infoBytes), L);
    }

    private Derivation derive(byte[] ikm, byte[] salt, byte[] infoBytes, String infoDisplay, int L) {
        if (ikm == null || ikm.length == 0) {
            throw new InvalidRequestException("INVALID_IKM", "ikm must not be empty");
        }
        if (L < 1 || L > MAX_OUTPUT) {
            throw new InvalidRequestException("INVALID_LENGTH",
                    "outputLength must be between 1 and " + MAX_OUTPUT);
        }
        byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
        if (infoBytes == null) {
            infoBytes = new byte[0];
        }

        List<String> steps = new ArrayList<>();

        // ---- Extract: PRK = HMAC-Hash(salt, IKM) ----
        byte[] prk = hmac(effectiveSalt, ikm);
        steps.add("EXTRACT  PRK = HMAC-SHA256(salt, ikm)");
        steps.add("           salt = " + hex(effectiveSalt) + " (" + effectiveSalt.length + " bytes"
                + ((salt == null || salt.length == 0) ? ", defaulted per RFC" : "") + ")");
        steps.add("           ikm  = " + hex(ikm) + " (" + ikm.length + " bytes)");
        steps.add("         → PRK  = " + hex(prk));

        // ---- Expand: OKM = HMAC(PRK, T(1) | T(2) | ...) ----
        int blocks = (L + HASH_LEN - 1) / HASH_LEN;
        byte[] okm = new byte[L];
        byte[] t = new byte[0];
        byte[] counter = new byte[1];
        int offset = 0;
        for (int i = 1; i <= blocks; i++) {
            counter[0] = (byte) i;
            t = hmac(prk, concat(t, infoBytes, counter));
            int chunk = Math.min(HASH_LEN, L - offset);
            System.arraycopy(t, 0, okm, offset, chunk);
            offset += chunk;
        }
        steps.add("EXPAND  OKM = HKDF-Expand(PRK, info, " + L + ")");
        steps.add("           info = \"" + infoDisplay + "\"  ← context label binds usage");
        steps.add("           T(i) = HMAC(PRK, T(i-1) | info | i)   for i = 1.." + blocks);
        steps.add("         → OKM  = " + hex(okm) + " (" + L + " bytes)");
        steps.add("Different info (or salt) ⇒ a completely different key — this is how two "
                + "directional session keys come from one shared secret.");

        return new Derivation(prk, okm, steps);
    }

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable", e);
        }
    }

    public static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) len += p.length;
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}