package com.rojan.cipherlab.lab.dto;

import java.util.List;

/**
 * Lab response bodies.
 *
 * <p>Representation decision (spec §5): AES outputs use
 * <b>separated {@code ciphertext} / {@code tag} fields</b> so the UI can
 * tamper with each independently. The tag also appears {@code combined}
 * ({@code ciphertext || tag}) in one Base64 string, demonstrating the wire
 * format real libraries use.
 */
public final class LabResponses {

    private LabResponses() {}

    public record Encrypt(
            String algorithm,
            String key,
            String nonce,
            String ciphertext,
            String tag,
            String combined,
            String securityNote) {}

    public record Decrypt(
            String algorithm,
            String plaintext,
            Boolean authenticated,
            String note) {}

    public record Hash(String algorithm, String digest) {}

    public record Hmac(String algorithm, String mac, String note) {}

    public record DiffieHellman(
            String p,
            String g,
            String alicePrivate,
            String bobPrivate,
            String alicePublic,
            String bobPublic,
            String sharedSecret,
            List<String> steps,
            String securityNote) {}

    public record Hkdf(
            String algorithm,
            String ikmB64,
            String saltB64,
            String info,
            Integer outputLength,
            String prkHex,
            String outputHex,
            List<String> steps,
            String securityNote) {}

    public record SignatureKeygen(
            String algorithm,
            String privateKey,
            String publicKey,
            String fingerprint,
            String securityNote) {}

    public record Signature(
            String algorithm,
            String signature,
            String messageSha256) {}

    public record SignatureVerification(Boolean valid, String fingerprint, String explanation) {}

    public record Mitm(
            String mode,
            List<String> participants,
            java.util.Map<String, String> sharedSecrets,
            Boolean malloryCanRead,
            Boolean substitutionDetected,
            List<String> steps,
            String securityNote) {}
}