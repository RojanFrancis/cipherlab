package com.rojan.cipherlab.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * The token pipeline, verified against the standard Nimbus-based decoder
 * that production uses ({@link JwtService#createDecoder()} is the single
 * construction site, shared by {@code SecurityConfig} and these tests).
 *
 * <p>Every attack that motivated the hand-rolled implementation's defensive
 * ordering is still covered here — algorithm confusion, tampering, expiry,
 * forged issuer — now proven against the library that actually ships.
 */
class JwtServiceTest {

    private static final String SECRET = "unit-test-secret-long-enough-for-hs256-0123456789";
    private static final String ISSUER = "cipherlab-api";

    private final JwtService service = new JwtService(SECRET, ISSUER, 3600, false);
    private final JwtDecoder decoder = service.createDecoder();

    // ------------------------------------------------------------- happy path

    @Test
    @DisplayName("Issue → verify roundtrip returns the original claims plus the issuer")
    void roundTrip() {
        UUID id = UUID.randomUUID();
        Jwt jwt = decoder.decode(service.issueToken(id, "alice"));

        assertEquals(id.toString(), jwt.getSubject());
        assertEquals("alice", jwt.getClaim("username"));
        assertEquals(ISSUER, jwt.getClaimAsString("iss"));
        assertNotNull(jwt.getIssuedAt());
        assertNotNull(jwt.getExpiresAt());
    }

    @Test
    @DisplayName("Unicode usernames survive the roundtrip")
    void unicodeUsername() {
        Jwt jwt = decoder.decode(service.issueToken(UUID.randomUUID(), "Zoë_Müller"));
        assertEquals("Zoë_Müller", jwt.getClaim("username"));
    }

    // ------------------------------------------------------------- tampering

    @Test
    @DisplayName("A tampered payload is rejected — the signature covers header.payload")
    void tamperedPayloadRejected() {
        String token = service.issueToken(UUID.randomUUID(), "alice");
        String[] parts = token.split("\\.");
        // Swap the payload for one claiming a different subject; keep the signature.
        String forgedJson = ("{'sub':'" + UUID.randomUUID()
                + "','username':'mallory','iss':'" + ISSUER
                + "','exp':9999999999}").replace('\'', '"');
        String forgedPayload = b64url(forgedJson.getBytes(StandardCharsets.UTF_8));
        String forged = parts[0] + "." + forgedPayload + "." + parts[2];

        assertThrows(JwtException.class, () -> decoder.decode(forged),
                "signature must not validate over a swapped payload");
    }

    @Test
    @DisplayName("A tampered signature segment is rejected")
    void tamperedSignatureRejected() {
        String token = service.issueToken(UUID.randomUUID(), "alice");
        String[] parts = token.split("\\.");
        String forged = parts[0] + "." + parts[1] + "." + b64url("not-a-real-signature".getBytes(StandardCharsets.UTF_8));

        assertThrows(JwtException.class, () -> decoder.decode(forged));
    }

    // ------------------------------------------------------------- algorithm & key attacks

    @Test
    @DisplayName("alg=none tokens are rejected — the classic algorithm-confusion attack")
    void algNoneRejected() {
        String header = b64url("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String forgedJson = ("{'sub':'" + UUID.randomUUID()
                + "','username':'mallory','iss':'" + ISSUER
                + "','exp':9999999999}").replace('\'', '"');
        String payload = b64url(forgedJson.getBytes(StandardCharsets.UTF_8));
        String forged = header + "." + payload + ".";

        assertThrows(JwtException.class, () -> decoder.decode(forged));
    }

    @Test
    @DisplayName("A token signed with a different secret is rejected")
    void wrongSecretRejected() {
        JwtService attacker = new JwtService(
                "attacker-secret-long-enough-for-hs256-0123456789", ISSUER, 3600, false);
        String token = attacker.issueToken(UUID.randomUUID(), "mallory");

        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    // ------------------------------------------------------------- claims validation

    @Test
    @DisplayName("An expired token is rejected even with a valid signature")
    void expiredTokenRejected() {
        JwtService expired = new JwtService(SECRET, ISSUER, -1, false);
        String token = expired.issueToken(UUID.randomUUID(), "alice");

        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    @DisplayName("A token with a different issuer is rejected")
    void wrongIssuerRejected() {
        JwtService otherIssuer = new JwtService(SECRET, "someone-elses-api", 3600, false);
        String token = otherIssuer.issueToken(UUID.randomUUID(), "alice");

        assertThrows(JwtException.class, () -> decoder.decode(token),
                "issuer must be validated, not trusted from the token");
    }

    @Test
    @DisplayName("Garbage and malformed tokens are rejected without throwing anything unchecked")
    void malformedTokensRejected() {
        assertThrows(JwtException.class, () -> decoder.decode("garbage"));
        assertThrows(JwtException.class, () -> decoder.decode("a.b.c"));
        assertThrows(JwtException.class, () -> decoder.decode(""));
        // Right shape, unparseable payload:
        String header = b64url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        assertThrows(JwtException.class, () -> decoder.decode(header + "." + b64url("{}".getBytes(StandardCharsets.UTF_8)) + ".x"));
    }

    // ------------------------------------------------------------- secret policy (fail-fast)

    @Test
    @DisplayName("The constructor refuses a secret shorter than 32 characters")
    void weakSecretRefused() {
        assertThrows(IllegalStateException.class, () -> new JwtService("tooshort", ISSUER, 3600, false));
    }

    @Test
    @DisplayName("The constructor refuses a missing/blank secret — production cannot boot without one")
    void blankSecretRefused() {
        assertThrows(IllegalStateException.class, () -> new JwtService("", ISSUER, 3600, false));
        assertThrows(IllegalStateException.class, () -> new JwtService(null, ISSUER, 3600, false));
    }

    @Test
    @DisplayName("The publicly known dev secret is refused unless the dev profile explicitly allows it")
    void knownDevSecretRefusedOutsideDev() {
        assertThrows(IllegalStateException.class, () -> new JwtService(
                JwtService.KNOWN_DEV_SECRET, ISSUER, 3600, false));
        // The dev profile path (allowDevSecret=true) still works:
        JwtService dev = new JwtService(JwtService.KNOWN_DEV_SECRET, ISSUER, 3600, true);
        assertNotNull(dev.issueToken(UUID.randomUUID(), "alice"));
    }

    // ------------------------------------------------------------- helpers

    private static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
