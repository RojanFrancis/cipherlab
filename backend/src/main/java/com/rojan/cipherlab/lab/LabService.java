package com.rojan.cipherlab.lab;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.stereotype.Service;

import com.rojan.cipherlab.common.AuthenticationFailedException;
import com.rojan.cipherlab.common.InvalidRequestException;
import com.rojan.cipherlab.crypto.aes.AesGcmService;
import com.rojan.cipherlab.crypto.hashing.HashingService;
import com.rojan.cipherlab.crypto.keyexchange.ToyDiffieHellmanService;
import com.rojan.cipherlab.crypto.signatures.SignatureService;
import com.rojan.cipherlab.lab.dto.LabRequests;
import com.rojan.cipherlab.lab.dto.LabResponses;

/**
 * Application layer for the Crypto Lab: converts between DTO encodings
 * (UTF-8 / Base64 / hex) and the byte-oriented crypto classes.
 *
 * <p>Boundary rule: this service validates that decoded material has the
 * exact lengths the primitives require (32/12/16 bytes) <em>before</em>
 * invoking JCA, so malformed input produces a clean 400 instead of an
 * {@link IllegalArgumentException} leaking into the error contract.
 */
@Service
public class LabService {

    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64_DEC = Base64.getDecoder();

    private final AesGcmService aes;
    private final HashingService hashing;
    private final ToyDiffieHellmanService diffieHellman;
    private final com.rojan.cipherlab.crypto.kdf.HkdfService hkdf;
    private final com.rojan.cipherlab.crypto.signatures.SignatureService signatures;
    private final com.rojan.cipherlab.crypto.mitm.MitmSimulation mitm;

    public LabService(AesGcmService aes, HashingService hashing, ToyDiffieHellmanService diffieHellman,
            com.rojan.cipherlab.crypto.kdf.HkdfService hkdf,
            com.rojan.cipherlab.crypto.signatures.SignatureService signatures,
            com.rojan.cipherlab.crypto.mitm.MitmSimulation mitm) {
        this.aes = aes;
        this.hashing = hashing;
        this.diffieHellman = diffieHellman;
        this.hkdf = hkdf;
        this.signatures = signatures;
        this.mitm = mitm;
    }

    public LabResponses.Encrypt encrypt(LabRequests.Encrypt request) {
        byte[] aad = decodeOptional("aad", request.aad());
        byte[] key = aes.generateKey(); // fresh lab key per experiment
        AesGcmService.EncryptedPayload payload =
                aes.encrypt(key, request.plaintext().getBytes(StandardCharsets.UTF_8), aad);

        byte[][] sealed = { payload.ciphertext(), payload.tag() };
        return new LabResponses.Encrypt(
                AesGcmService.TRANSFORMATION,
                B64.encodeToString(key),
                B64.encodeToString(payload.nonce()),
                B64.encodeToString(payload.ciphertext()),
                B64.encodeToString(payload.tag()),
                B64.encodeToString(AesGcmService.join(sealed[0], sealed[1])),
                "LAB ONLY: this key was generated server-side for the experiment. "
                        + "Real secure-channel keys are derived client-side and never leave the browser.");
    }

    public LabResponses.Decrypt decrypt(LabRequests.Decrypt request) {
        byte[] key = decode("key", request.key(), AesGcmService.KEY_BYTES);
        byte[] nonce = decode("nonce", request.nonce(), AesGcmService.NONCE_BYTES);
        byte[] tag = decode("tag", request.tag(), AesGcmService.TAG_BYTES);
        byte[] ciphertext = B64_DEC.decode(request.ciphertext()); // length flexible
        byte[] aad = decodeOptional("aad", request.aad());

        byte[] plaintext;
        try {
            plaintext = aes.decrypt(key, nonce, ciphertext, tag, aad);
        } catch (AuthenticationFailedException e) {
            throw e; // pass through with the spec's INVALID_CIPHERTEXT mapping
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new InvalidRequestException("INVALID_CIPHERTEXT_INPUT", e.getMessage());
        }
        return new LabResponses.Decrypt(
                AesGcmService.TRANSFORMATION,
                new String(plaintext, StandardCharsets.UTF_8),
                Boolean.TRUE, // reaching here means the tag verified
                "authenticated: GCM verified the 128-bit tag before releasing any plaintext");
    }

    public LabResponses.Hash hash(LabRequests.Hash request) {
        return new LabResponses.Hash(request.algorithm(), hashing.digest(request.input(), request.algorithm()));
    }

    public LabResponses.Hmac hmac(LabRequests.Hmac request) {
        return new LabResponses.Hmac(HashingService.HMAC_ALGORITHM, hashing.hmac(request.key(), request.input()),
                "HMAC proves integrity + sender knew the key; it does not prove identity to a third party.");
    }

    public LabResponses.DiffieHellman diffieHellman(LabRequests.DiffieHellman request) {
        ToyDiffieHellmanService.DhExchange x = diffieHellman.exchange(
                request.p(), request.g(), request.alicePrivate(), request.bobPrivate());
        return new LabResponses.DiffieHellman(
                x.p(), x.g(), x.alicePrivate(), x.bobPrivate(),
                x.alicePublic(), x.bobPublic(), x.sharedSecret(), x.steps(),
                "TOY VALUES: mathematically correct but unauthenticated. Never usable as keys "
                        + "by the secure messaging module.");
    }

    public LabResponses.Hkdf hkdf(LabRequests.Hkdf request) {
        byte[] ikm;
        byte[] salt;
        try {
            ikm = B64_DEC.decode(request.ikm());
            salt = (request.salt() == null || request.salt().isEmpty()) ? null : B64_DEC.decode(request.salt());
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("INVALID_BASE64", "ikm and salt must be valid Base64");
        }
        com.rojan.cipherlab.crypto.kdf.HkdfService.Derivation d =
                hkdf.derive(ikm, salt, request.info(), request.outputLength());
        return new LabResponses.Hkdf(
                "HKDF-SHA-256 (RFC 5869)",
                request.ikm(), request.salt(), request.info(), request.outputLength(),
                com.rojan.cipherlab.crypto.kdf.HkdfService.hex(d.prk()),
                com.rojan.cipherlab.crypto.kdf.HkdfService.hex(d.okm()),
                d.steps(),
                "The raw DH secret is NOT an AES key — HKDF extracts and expands it into "
                        + "context-bound key material. Different info ⇒ different keys.");
    }

    public LabResponses.SignatureKeygen signatureKeygen() {
        var pair = signatures.generate();
        return new LabResponses.SignatureKeygen(
                SignatureService.API_ALGORITHM, pair.privateKey(), pair.publicKey(), pair.fingerprint(),
                "LAB ONLY: this private key is displayed on purpose — real identity keys never "
                        + "leave the client holding them.");
    }

    public LabResponses.Signature sign(LabRequests.Sign request) {
        String signature = signatures.sign(request.privateKey(), request.message());
        return new LabResponses.Signature(
                SignatureService.API_ALGORITHM, signature,
                hashing.digest(request.message(), "SHA-256"));
    }

    public LabResponses.SignatureVerification verify(LabRequests.Verify request) {
        var result = signatures.verify(request.publicKey(), request.message(), request.signature());
        return new LabResponses.SignatureVerification(
                result.valid(), signatures.fingerprintOf(request.publicKey()), result.explanation());
    }

    public LabResponses.Mitm mitm(LabRequests.Mitm request) {
        var sim = mitm.simulate(request.mode().trim().toLowerCase(java.util.Locale.ROOT));
        return new LabResponses.Mitm(
                sim.mode(), sim.participants(), sim.sharedSecrets(),
                sim.malloryCanRead(), sim.substitutionDetected(), sim.steps(), sim.securityNote());
    }

    private static byte[] decode(String field, String value, int expectedLength) {
        byte[] bytes;
        try {
            bytes = B64_DEC.decode(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("INVALID_BASE64", field + " is not valid Base64");
        }
        if (bytes.length != expectedLength) {
            throw new InvalidRequestException("INVALID_LENGTH",
                    field + " must decode to exactly " + expectedLength + " bytes, got " + bytes.length);
        }
        return bytes;
    }

    private static byte[] decodeOptional(String field, String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return B64_DEC.decode(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("INVALID_BASE64", field + " is not valid Base64");
        }
    }
}