package com.rojan.cipherlab.crypto.signatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.rojan.cipherlab.common.InvalidRequestException;
import com.rojan.cipherlab.crypto.hashing.HashingService;

class SignatureServiceTest {

    private final SignatureService service = new SignatureService();

    @Test
    @DisplayName("sign → verify roundtrip succeeds and fingerprint is stable")
    void roundTrip() {
        var key = service.generate();
        String sig = service.sign(key.privateKey(), "I approve transaction #42");

        var result = service.verify(key.publicKey(), "I approve transaction #42", sig);
        assertTrue(result.valid());
        assertEquals(64, key.fingerprint().length(), "SHA-256 hex fingerprint");
        assertEquals(key.fingerprint(), service.fingerprintOf(key.publicKey()));
        assertNotEquals(key.fingerprint(), service.generate().fingerprint(), "fresh keys → new fingerprint");
    }

    @Test
    @DisplayName("modified message fails verification")
    void tamperedMessageFails() {
        var key = service.generate();
        String sig = service.sign(key.privateKey(), "transfer 100 to alice");
        var result = service.verify(key.publicKey(), "transfer 100 to mallory", sig);
        assertFalse(result.valid());
        assertTrue(result.explanation().contains("modified"));
    }

    @Test
    @DisplayName("wrong public key fails verification — signature doesn't transfer between identities")
    void wrongKeyFails() {
        var honest = service.generate();
        var mallory = service.generate();
        String sig = service.sign(honest.privateKey(), "genuine message");

        // Mallory cannot make Alice's signature verify against Mallory's key…
        assertFalse(service.verify(mallory.publicKey(), "genuine message", sig).valid());
        // …and cannot forge Alice's signature at all with her own private key:
        String forged = service.sign(mallory.privateKey(), "genuine message");
        assertFalse(service.verify(honest.publicKey(), "genuine message", forged).valid(),
                "identity binding: only Alice's key verifies Alice's signature");
    }

    @Test
    @DisplayName("malformed signature/key inputs fail closed, never throw 500s")
    void malformedInputsFailClosed() {
        var key = service.generate();
        assertFalse(service.verify(key.publicKey(), "msg", "!!not-base64!!").valid());
        assertThrows(InvalidRequestException.class,
                () -> service.verify("!!!invalid!!!", "msg", "AAAA"));
        assertThrows(InvalidRequestException.class,
                () -> service.sign("!!!invalid!!!", "msg"));
        // Valid Base64 but not an EC key: clean 400 (fail-closed client error, not a silent false).
        assertThrows(InvalidRequestException.class, () -> service.verify(
                java.util.Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}),
                "msg", "AAAA"));
    }

    @Test
    @DisplayName("two signatures of the same message differ (ECDSA nonce) — not a bug")
    void signaturesAreRandomized() {
        var key = service.generate();
        String s1 = service.sign(key.privateKey(), "same message");
        String s2 = service.sign(key.privateKey(), "same message");
        assertNotEquals(s1, s2, "ECDSA uses a per-signature random nonce");
        assertTrue(service.verify(key.publicKey(), "same message", s1).valid());
        assertTrue(service.verify(key.publicKey(), "same message", s2).valid());
    }

    @Test
    @DisplayName("fingerprint is SHA-256 of the X.509 public key encoding (verifiable out of band)")
    void fingerprintBindsToKeyBytes() {
        var key = service.generate();
        byte[] raw = java.util.Base64.getDecoder().decode(key.publicKey());
        String manual = new HashingService().digestBytes(raw, "SHA-256");
        assertEquals(manual, service.fingerprintOf(key.publicKey()));
    }
}