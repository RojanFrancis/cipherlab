package com.rojan.cipherlab.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Minimal, self-contained HMAC-SHA256 JWT implementation (RFC 7519 + RFC 7515).
 *
 * <p>Hand-rolled on purpose: for a cryptography learning lab, every step of
 * token construction — base64url segments, the {@code HMAC(header.payload)}
 * signature, the verification order — is visible and auditable, rather than
 * hidden behind a dependency. The primitives used are exactly the JCA ones
 * taught in the lab ({@link Mac} with {@code HmacSHA256}).
 *
 * <p><b>Security properties enforced here:</b>
 * <ul>
 *   <li><b>Algorithm confusion is impossible</b> — the {@code alg} header is
 *       verified to be exactly {@code HS256}; {@code none} or swapped
 *       algorithms are rejected before any crypto runs. (The classic
 *       {@code alg=none} attack.)</li>
 *   <li><b>Constant-time signature comparison</b> — {@link MessageDigest#isEqual}
 *       avoids the timing side channel of {@code String.equals} on MACs.</li>
 *   <li><b>Expiry is checked</b> — an expired token is rejected even when the
 *       signature is valid.</li>
 *   <li><b>The secret never appears in tokens or logs</b>; it is injected via
 *       configuration ({@code JWT_SECRET}) and read once at startup.</li>
 * </ul>
 *
 * <p>A token is three base64url segments: {@code header.payload.signature}.
 * Clients must treat it as opaque; only the signature makes the claims
 * trustworthy — unsigned claims are just attacker-editable JSON.
 */
@Service
public class JwtService {

    private static final String ALGORITHM = "HmacSHA256";
    private static final String ALG_HEADER = "HS256";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_DECODER = Base64.getUrlDecoder();

    /** header.payload.signature — no dots anywhere else. */
    private static final Pattern TOKEN_FORMAT =
            Pattern.compile("^([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)$");

    private static final String HEADER_JSON = "{\"alg\":\"" + ALG_HEADER + "\",\"typ\":\"JWT\"}";

    private final SecretKeySpec key;
    private final long ttlSeconds;

    public JwtService(@Value("${cipherlab.security.jwt-secret}") String secret,
                      @Value("${cipherlab.security.jwt-ttl-seconds:3600}") long ttlSeconds) {
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException(
                    "cipherlab.security.jwt-secret must be at least 32 characters; set JWT_SECRET");
        }
        this.key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        this.ttlSeconds = ttlSeconds;
    }

    /**
     * Issue a signed token for a user. Claims: {@code sub} (user id),
     * {@code username}, {@code iat}, {@code exp} — all epoch seconds.
     */
    public String issueToken(UUID userId, String username) {
        long now = Instant.now().getEpochSecond();
        String header = B64.encodeToString(HEADER_JSON.getBytes(StandardCharsets.UTF_8));
        String payload = B64.encodeToString(("{\"sub\":\"" + userId
                + "\",\"username\":\"" + jsonEscape(username)
                + "\",\"iat\":" + now + ",\"exp\":" + (now + ttlSeconds) + "}")
                .getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + B64.encodeToString(hmac(header + "." + payload));
    }

    /**
     * Verify a token and return its claims, or {@code null} if the token is
     * malformed, tampered with, uses the wrong algorithm, or has expired.
     *
     * <p>Verification order matters: format → alg → signature → expiry. The
     * signature is checked <em>before</em> the claims are trusted for
     * anything, and expiry is checked after — a forged exp claim cannot
     * survive a bad signature.
     */
    public Claims verify(String token) {
        if (token == null) {
            return null;
        }
        Matcher matcher = TOKEN_FORMAT.matcher(token);
        if (!matcher.matches()) {
            return null;
        }
        String headerSegment = matcher.group(1);
        String payloadSegment = matcher.group(2);
        byte[] signature = B64_DECODER.decode(matcher.group(3));

        // 1) Algorithm confusion defense: only HS256 is acceptable.
        String headerJson;
        try {
            headerJson = new String(B64_DECODER.decode(headerSegment), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!headerJson.contains("\"alg\":\"" + ALG_HEADER + "\"")) {
            return null;
        }

        // 2) Constant-time MAC comparison over header.payload.
        byte[] expected = hmac(headerSegment + "." + payloadSegment);
        if (!MessageDigest.isEqual(expected, signature)) {
            return null;
        }

        // 3) Claims are now trustworthy — parse and check expiry.
        String payloadJson;
        try {
            payloadJson = new String(B64_DECODER.decode(payloadSegment), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        String sub = claim(payloadJson, "sub");
        String username = claim(payloadJson, "username");
        String exp = claim(payloadJson, "exp");
        if (sub == null || username == null || exp == null) {
            return null;
        }
        UUID userId;
        long expSeconds;
        try {
            userId = UUID.fromString(sub);
            expSeconds = Long.parseLong(exp);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (Instant.now().getEpochSecond() >= expSeconds) {
            return null;
        }
        return new Claims(userId, username, expSeconds);
    }

    private byte[] hmac(String data) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /** Extract a top-level string/number claim from a flat JSON object. */
    private static String claim(String json, String name) {
        Matcher matcher = Pattern.compile("\"" + name + "\":\"?([^,\"}]+)\"?").matcher(json);
        return matcher.find() ? matcher.group(1) : null;
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** Verified token claims. */
    public record Claims(UUID userId, String username, long expiresAt) {
    }
}
