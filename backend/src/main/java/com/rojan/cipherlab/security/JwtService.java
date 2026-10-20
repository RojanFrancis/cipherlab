package com.rojan.cipherlab.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import javax.crypto.spec.SecretKeySpec;

/**
 * Access-token <b>issuance</b> built on the standard Nimbus JOSE+JWT library
 * (via Spring Security's OAuth2 stack) — no hand-rolled parsing, header
 * handling or claim extraction anywhere in this codebase.
 *
 * <p><b>Token verification</b> is equally standard: {@link #createDecoder()}
 * produces the {@link JwtDecoder} that {@code SecurityConfig} installs into
 * Spring Security's resource-server filter. That decoder enforces, per
 * request: HS256 signature (algorithm-confusion and {@code alg=none} are
 * rejected by the library itself), <b>issuer</b>, and <b>expiry</b> — in
 * that trust order, before any claim is acted upon.
 *
 * <p><b>Secret policy</b> (fail-fast at startup, in every profile):
 * <ul>
 *   <li>missing/blank → {@link IllegalStateException}: production cannot boot
 *       without {@code JWT_SECRET};</li>
 *   <li>shorter than 32 characters → refused (HS256's minimum key size);</li>
 *   <li>the well-known public development value → refused unless the active
 *       profile explicitly allows it ({@code cipherlab.security.allow-dev-secret},
 *       set only in {@code application-dev.yml}). A publicly known secret is
 *       no secret: anyone could mint tokens for any user.</li>
 * </ul>
 *
 * <p>The secret is read once at startup and never logged, echoed or embedded
 * in any response. Tokens carry {@code sub} (user id), {@code username},
 * {@code iss}, {@code iat}, {@code exp}.
 */
@Service
public class JwtService {

    /**
     * The historical development default. It is intentionally left public so
     * that its presence anywhere outside the dev profile can be detected and
     * refused — a known signing key means forgable tokens.
     */
    public static final String KNOWN_DEV_SECRET =
            "dev-only-jwt-secret-do-not-use-in-production-0123456789";

    public static final int MIN_SECRET_LENGTH = 32;

    private final SecretKeySpec key;
    private final String issuer;
    private final long ttlSeconds;

    public JwtService(@Value("${cipherlab.security.jwt-secret}") String secret,
                      @Value("${cipherlab.security.jwt-issuer}") String issuer,
                      @Value("${cipherlab.security.jwt-ttl-seconds:3600}") long ttlSeconds,
                      @Value("${cipherlab.security.allow-dev-secret:false}") boolean allowDevSecret) {
        validateSecret(secret, allowDevSecret);
        this.key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        this.issuer = issuer;
        this.ttlSeconds = ttlSeconds;
    }

    /**
     * Startup policy, also invoked directly by the {@code JwtDecoder} bean so
     * both halves of the pipeline agree. Throws {@link IllegalStateException}
     * (failing application startup) when the secret is unusable.
     */
    public static void validateSecret(String secret, boolean allowDevSecret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(
                    "cipherlab.security.jwt-secret is not set. Set JWT_SECRET (min 32 random chars); "
                            + "the application refuses to run without an explicit signing secret.");
        }
        if (secret.length() < MIN_SECRET_LENGTH) {
            throw new IllegalStateException(
                    "cipherlab.security.jwt-secret must be at least " + MIN_SECRET_LENGTH
                            + " characters (HS256 minimum key size); set JWT_SECRET.");
        }
        if (!allowDevSecret && KNOWN_DEV_SECRET.equals(secret)) {
            throw new IllegalStateException(
                    "cipherlab.security.jwt-secret is the publicly known development default. "
                            + "Outside the dev profile this is refused: anyone holding it could mint "
                            + "tokens for any user. Set a fresh JWT_SECRET.");
        }
    }

    /**
     * Issue a signed token for a user. Claims: {@code sub} (user id),
     * {@code username}, {@code iss}, {@code iat}, {@code exp}.
     */
    public String issueToken(UUID userId, String username) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(userId.toString())
                    .claim("username", username)
                    .issuer(issuer)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(ttlSeconds)))
                    .build();
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.HS256).build(), claims);
            jwt.sign(new MACSigner(key.getEncoded()));
            return jwt.serialize();
        } catch (Exception e) {
            // Never surfaces token or key material — a signing failure is an
            // infrastructure problem, not something to enrich an error with.
            throw new IllegalStateException("Could not sign access token", e);
        }
    }

    /**
     * The single construction site for the verifying {@link JwtDecoder}:
     * HS256 with the same secret, plus the standard validator set extended
     * with issuer checking. Used by {@code SecurityConfig} and by tests, so
     * what production verifies is exactly what tests verify.
     */
    public JwtDecoder createDecoder() {
        // A symmetric SecretKey selects HS256 by default; anything else in
        // the header (alg=none, RSA, …) is rejected by the JOSE processor.
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }

    public String issuer() {
        return issuer;
    }

    public long ttlSeconds() {
        return ttlSeconds;
    }
}
