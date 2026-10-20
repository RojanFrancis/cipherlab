package com.rojan.cipherlab.crypto.signatures;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

import org.springframework.stereotype.Component;

import com.rojan.cipherlab.common.InvalidRequestException;

/**
 * ECDSA P-256 digital signatures — sender authenticity + integrity.
 *
 * <h2>Hash vs HMAC vs signature (the distinction the lab must teach)</h2>
 * <ul>
 *   <li>Hash: detects change <em>if</em> you already trust a digest.</li>
 *   <li>HMAC: proves sender knew a shared secret — both sides can forge.</li>
 *   <li>Signature: only the holder of the private key can produce it; anyone
 *       holding the public key can verify. This asymmetry is what
 *       authenticates a key exchange (preventing MITM).</li>
 * </ul>
 *
 * <h2>Which bytes actually get signed?</h2>
 * ECDSA signs a <em>hash</em> of the message (JCA applies SHA-256
 * internally). The signature never covers the raw text directly — key point
 * for students: signatures and hashes compose; replacing the message breaks
 * verification because the recomputed hash no longer matches.
 *
 * <p>Lab keys are generated fresh per request and displayed only in toy
 * demonstrations (spec rule: private values appear only in deliberately
 * insecure demos).
 */
@Component
public class SignatureService {

    public static final String CURVE = "secp256r1";           // NIST P-256
    public static final String KEY_ALGORITHM = "EC";
    public static final String SIG_ALGORITHM = "SHA256withECDSA";
    public static final String API_ALGORITHM = "ECDSA P-256 / SHA-256";

    /** Fresh lab keypair, encoded the way wire protocols carry keys. */
    public record LabKeyPair(String privateKey, String publicKey, String fingerprint) {}

    /** Generates a P-256 keypair; Base64(PKCS#8 private), Base64(X.509 public). */
    public LabKeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            generator.initialize(new ECGenParameterSpec(CURVE));
            KeyPair pair = generator.generateKeyPair();
            return new LabKeyPair(
                    Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                    Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                    fingerprint(pair.getPublic()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("EC P-256 keygen unavailable", e);
        }
    }

    /** Signs UTF-8 message bytes; returns Base64(DER-encoded signature). */
    public String sign(String privateKeyB64, String message) {
        PrivateKey privateKey = decodePrivate(privateKeyB64);
        try {
            Signature signer = Signature.getInstance(SIG_ALGORITHM);
            signer.initSign(privateKey);
            signer.update(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ECDSA signing unavailable", e);
        }
    }

    /**
     * Verifies a signature. Returns the boolean + a human explanation the
     * UI shows verbatim — three distinct failure causes exist (wrong key /
     * modified message / malformed signature) and JCA intentionally does not
     * tell you which, to prevent oracle-style leaks.
     */
    public Verification verify(String publicKeyB64, String message, String signatureB64) {
        PublicKey publicKey = decodePublic(publicKeyB64);
        byte[] sigBytes;
        try {
            sigBytes = Base64.getDecoder().decode(signatureB64);
        } catch (IllegalArgumentException e) {
            return new Verification(false,
                    "Signature bytes are not valid Base64 — verification fails closed.");
        }
        try {
            Signature verifier = Signature.getInstance(SIG_ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(message.getBytes(StandardCharsets.UTF_8));
            boolean valid = verifier.verify(sigBytes);
            return valid
                    ? new Verification(true, "The signature matches this public key and message: "
                            + "the signer held the private key and the message is intact.")
                    : new Verification(false, "Verification failed. Either the message was modified, "
                            + "the wrong public key was used, or the signature is malformed — "
                            + "ECDSA deliberately does not reveal which.");
        } catch (GeneralSecurityException e) {
            // Malformed DER or wrong key type: fail closed, never throw 500.
            return new Verification(false, "The signature could not be parsed for this public key "
                    + "— verification fails closed.");
        }
    }

    /** SHA-256 over the X.509 public-key bytes — what users compare as a "fingerprint". */
    public String fingerprint(PublicKey publicKey) {
        try {
            // Exactly one hash pass: fingerprint = SHA-256(publicKey.getEncoded()).
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
            return HexFormat.of().formatHex(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Fingerprint of a Base64 X.509 public key — used after verification. */
    public String fingerprintOf(String publicKeyB64) {
        return fingerprint(decodePublic(publicKeyB64));
    }

    public record Verification(boolean valid, String explanation) {}

    private static PrivateKey decodePrivate(String b64) {
        byte[] der;
        try {
            der = Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("INVALID_KEY", "privateKey is not valid Base64");
        }
        try {
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new InvalidRequestException("INVALID_KEY", "privateKey is not a valid EC PKCS#8 key");
        }
    }

    private static PublicKey decodePublic(String b64) {
        byte[] der;
        try {
            der = Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("INVALID_KEY", "publicKey is not valid Base64");
        }
        try {
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new InvalidRequestException("INVALID_KEY", "publicKey is not a valid EC X.509 key");
        }
    }
}