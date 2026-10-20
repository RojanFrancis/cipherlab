package com.rojan.cipherlab.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the hand-rolled HS256 JWT implementation — including the
 * two attacks that break naive implementations: {@code alg=none} and
 * signature tampering.
 */
class JwtServiceTest {

    private static final String SECRET = "unit-test-secret-at-least-32-chars-long!";
    private static final String OTHER_SECRET = "a-completely-different-32-char-secret!!";

    private final JwtService service = new JwtService(SECRET, 3600);

    @Test
    @DisplayName("Issue → verify roundtrip returns the original claims")
    void roundTrip() {
        UUID userId = UUID.randomUUID();
        String token = service.issueToken(userId, "alice");

        JwtService.Claims claims = service.verify(token);

        assertNotNull(claims);
        assertEquals(userId, claims.userId());
        assertEquals("alice", claims.username());
        assertEquals(Instant.now().getEpochSecond() + 3600, claims.expiresAt(), 5);
    }

    @Test
    @DisplayName("Unicode usernames survive the roundtrip")
    void unicodeUsername() {
        String token = service.issueToken(UUID.randomUUID(), "aliça-🔑");
        JwtService.Claims claims = service.verify(token);
        assertNotNull(claims);
        assertEquals("aliça-🔑", claims.username());
    }

    @Test
    @DisplayName("A tampered payload is rejected (signature covers header.payload)")
    void tamperedPayloadRejected() {
        String token = service.issueToken(UUID.randomUUID(), "alice");
        String[] parts = token.split("\\.");

        // Forge a payload claiming a different user, keep the original signature.
        String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"sub\":\"" + UUID.randomUUID() + "\",\"username\":\"mallory\","
                        + "\"iat\":1,\"exp\":9999999999}").getBytes(StandardCharsets.UTF_8));
        String forged = parts[0] + "." + forgedPayload + "." + parts[2];

        assertNull(service.verify(forged));
    }

    @Test
    @DisplayName("A tampered signature segment is rejected")
    void tamperedSignatureRejected() {
        String token = service.issueToken(UUID.randomUUID(), "alice");
        String[] parts = token.split("\\.");
        byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
        sig[0] ^= 0x01; // flip one bit
        String forged = parts[0] + "." + parts[1] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

        assertNull(service.verify(forged));
    }

    @Test
    @DisplayName("alg=none tokens are rejected — the classic algorithm-confusion attack")
    void algNoneRejected() {
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"sub\":\"" + UUID.randomUUID() + "\",\"username\":\"mallory\","
                        + "\"iat\":1,\"exp\":9999999999}").getBytes(StandardCharsets.UTF_8));
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

        assertNull(service.verify(header + "." + payload + "."));
        assertNull(service.verify(header + "." + payload + ".anything"));
    }

    @Test
    @DisplayName("A token signed with a different secret is rejected")
    void wrongSecretRejected() {
        JwtService attacker = new JwtService(OTHER_SECRET, 3600);
        String token = attacker.issueToken(UUID.randomUUID(), "mallory");

        assertNull(service.verify(token));
    }

    @Test
    @DisplayName("An expired token is rejected even with a valid signature")
    void expiredTokenRejected() {
        JwtService shortLived = new JwtService(SECRET, -10); // already expired at issue
        String token = shortLived.issueToken(UUID.randomUUID(), "alice");

        assertNull(service.verify(token));
    }

    @Test
    @DisplayName("Garbage and null tokens are rejected without throwing")
    void malformedTokensRejected() {
        assertNull(service.verify(null));
        assertNull(service.verify(""));
        assertNull(service.verify("not-a-jwt"));
        assertNull(service.verify("a.b"));
        assertNull(service.verify("a.b.c.d"));
        assertNull(service.verify("!!.!!.!!"));
    }

    @Test
    @DisplayName("The constructor refuses a secret shorter than 32 characters")
    void weakSecretRefused() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> new JwtService("too-short", 3600));
    }
}
