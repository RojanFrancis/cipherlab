package com.rojan.cipherlab.crypto.hashing;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import com.rojan.cipherlab.common.InvalidRequestException;

/**
 * SHA-2 family hashing and HMAC — the integrity/authenticity primitives.
 *
 * <h2>Three things students confuse; CipherLab keeps them distinct</h2>
 * <ul>
 *   <li><b>Hash (SHA-256):</b> one-way fingerprint. Detects <em>change</em>
 *       only when compared against a digest you already trust. It proves no
 *       authorship — anyone can hash a message with the same algorithm.</li>
 *   <li><b>HMAC-SHA-256:</b> hash under a shared secret. Proves the sender
 *       knew the key <em>and</em> the message is intact. Symmetric: both
 *       sides can forge each other's MACs.</li>
 *   <li><b>Signature (ECDSA/RSA):</b> asymmetric authorship proof — see the
 *       signatures module.</li>
 * </ul>
 *
 * <p>Digests are returned as lowercase hex (unambiguous on screen) rather
 * than Base64, because learners compare them character by character.
 */
@Component
public class HashingService {

    /** Algorithm whitelist — no MD5/SHA-1, ever. */
    public static final Set<String> SUPPORTED_DIGESTS = Set.of("SHA-256", "SHA-512");
    public static final String HMAC_ALGORITHM = "HmacSHA256";

    /** One-way digest of UTF-8 input, lowercase hex. */
    public String digest(String input, String algorithm) {
        if (!SUPPORTED_DIGESTS.contains(algorithm)) {
            throw new InvalidRequestException("UNSUPPORTED_ALGORITHM",
                    "Unsupported digest algorithm. Allowed: " + SUPPORTED_DIGESTS);
        }
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            return HexFormat.of().formatHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Digest unavailable: " + algorithm, e);
        }
    }

    /** Keyed message authentication code, lowercase hex. */
    public String hmac(String key, String input) {
        if (key == null || key.isEmpty()) {
            throw new InvalidRequestException("INVALID_KEY", "HMAC key must not be empty");
        }
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            return HexFormat.of().formatHex(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable", e);
        }
    }

    /** Digest of a byte array — used by fingerprint displays. */
    public String digestBytes(byte[] data, String algorithm) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Digest unavailable: " + algorithm, e);
        }
    }
}