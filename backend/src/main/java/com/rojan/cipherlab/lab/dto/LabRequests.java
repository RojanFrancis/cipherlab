package com.rojan.cipherlab.lab.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Validated lab request bodies.
 *
 * <p>Payload caps keep a classroom demo from becoming a denial-of-service
 * vector: 8 KiB for text inputs, and decimal-string DH parameters (Jackson
 * numbers lose precision beyond 2^53 in browsers, so the spec's toy DH
 * fields travel as validated decimal strings).
 */
public final class LabRequests {

    private LabRequests() {}

    /** POST /api/v1/lab/aes/encrypt — spec field list: {@code plaintext}. */
    public record Encrypt(
            @NotBlank @Size(max = 8192) String plaintext,
            @Size(max = 8192) String aad) {}

    /**
     * POST /api/v1/lab/aes/decrypt — spec fields: key, nonce, ciphertext, tag.
     * All Base64; decoded lengths are checked in the service (32/12/16 bytes).
     */
    public record Decrypt(
            @NotBlank @Size(max = 128) String key,
            @NotBlank @Size(max = 64) String nonce,
            @NotBlank @Size(max = 24576) String ciphertext,
            @NotBlank @Size(max = 64) String tag,
            @Size(max = 8192) String aad) {}

    /** POST /api/v1/lab/hash — fields: input, algorithm. */
    public record Hash(
            @NotBlank @Size(max = 8192) String input,
            @NotBlank @Size(max = 16) String algorithm) {}

    /** POST /api/v1/lab/hmac — fields: input, key. */
    public record Hmac(
            @NotBlank @Size(max = 8192) String input,
            @NotBlank @Size(max = 4096) String key) {}

    /** POST /api/v1/lab/diffie-hellman — toy mode only, spec fields p, g, alicePrivate, bobPrivate. */
    public record DiffieHellman(
            @NotBlank @Pattern(regexp = "\\d{1,160}", message = "must be a decimal integer") String p,
            @NotBlank @Pattern(regexp = "\\d{1,160}", message = "must be a decimal integer") String g,
            @NotBlank @Pattern(regexp = "\\d{1,160}", message = "must be a decimal integer") String alicePrivate,
            @NotBlank @Pattern(regexp = "\\d{1,160}", message = "must be a decimal integer") String bobPrivate) {}

    /** POST /api/v1/lab/hkdf (spec §5): ikm/salt Base64, info UTF-8 context, outputLength 1..8160 (RFC bound). */
    public record Hkdf(
            @NotBlank @Size(max = 512) String ikm,
            @Size(max = 512) String salt,
            @Size(max = 2048) String info,
            @Min(1) @Max(8160) int outputLength) {}

    /** POST /api/v1/lab/signatures/sign (spec §5): message + lab key. */
    public record Sign(
            @NotBlank @Size(max = 8192) String message,
            @NotBlank @Size(max = 512) String privateKey) {}

    /** POST /api/v1/lab/signatures/verify (spec §5). */
    public record Verify(
            @NotBlank @Size(max = 8192) String message,
            @NotBlank @Size(max = 1024) String signature,
            @NotBlank @Size(max = 512) String publicKey) {}

    /** POST /api/v1/lab/mitm/simulate — controlled local simulation only. */
    public record Mitm(
            @NotBlank @Pattern(regexp = "unauthenticated|authenticated", message = "must be unauthenticated or authenticated")
            String mode) {}
}