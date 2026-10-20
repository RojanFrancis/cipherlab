package com.rojan.cipherlab.identity;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.rojan.cipherlab.common.AuditService;
import com.rojan.cipherlab.common.ConflictException;
import com.rojan.cipherlab.common.NotFoundException;
import com.rojan.cipherlab.crypto.hashing.HashingService;

/**
 * Public identity key registry.
 *
 * <p>The threat this exists to solve (spec §2): an attacker who controls the
 * server can hand out <em>their own</em> public key to Alice when she asks
 * for Bob's — the classic key-substitution / MITM move the lab simulates.
 * Publishing keys with <b>fingerprints</b> gives users an out-of-band value
 * they can compare ("does your fingerprint end in 7F3A?"), which no server
 * can silently rewrite.
 *
 * <p>Client-generated, client-held rule: the server only ever receives the
 * <b>public</b> half. If this table leaks, no private material leaks with
 * it. Rotation increments {@code key_version} instead of overwriting, so
 * signatures made under the old key stay verifiable and revocation is an
 * explicit, auditable act.
 */
@Service
public class IdentityKeyService {

    private final IdentityKeyRepository identityKeyRepository;
    private final AuditService auditService;
    private final HashingService hashingService;

    public IdentityKeyService(IdentityKeyRepository identityKeyRepository,
                              AuditService auditService,
                              HashingService hashingService) {
        this.identityKeyRepository = identityKeyRepository;
        this.auditService = auditService;
        this.hashingService = hashingService;
    }

    /**
     * Publish a public key for the current user. {@code keyType} is
     * constrained to the types the lab teaches ({@code EC_P256},
     * {@code RSA_2048}); the fingerprint is recomputed server-side from the
     * submitted key bytes — a client-supplied fingerprint would defeat the
     * whole point.
     */
    @Transactional
    public KeyResponse publish(UUID userId, String keyType, String publicKeyBase64) {
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        } catch (IllegalArgumentException e) {
            throw new com.rojan.cipherlab.common.InvalidRequestException(
                    "INVALID_KEY", "The public key must be Base64-encoded.");
        }
        if (keyBytes.length == 0 || keyBytes.length > 384) {
            throw new com.rojan.cipherlab.common.InvalidRequestException(
                    "INVALID_KEY", "Public key must decode to 1-384 bytes.");
        }
        int nextVersion = identityKeyRepository.countByUserId(userId) + 1;
        String fingerprint = hashingService.digestBytes(keyBytes, "SHA-256");
        IdentityKey key = identityKeyRepository.save(
                IdentityKey.create(userId, keyType, publicKeyBase64, fingerprint, nextVersion));
        auditService.record(userId, "IDENTITY_KEY_PUBLISHED", key.getId().toString());
        return KeyResponse.of(key);
    }

    /** The user's key history, newest version first. */
    @Transactional(readOnly = true)
    public List<KeyResponse> listMine(UUID userId) {
        return identityKeyRepository.findByUserIdOrderByKeyVersionDesc(userId).stream()
                .map(KeyResponse::of)
                .toList();
    }

    /** Revoke a key the caller owns. Revocation is final — never deleted. */
    @Transactional
    public KeyResponse revoke(UUID userId, UUID keyId) {
        IdentityKey key = identityKeyRepository.findByIdAndUserId(keyId, userId)
                .orElseThrow(NotFoundException::new);
        if (key.isRevoked()) {
            throw new ConflictException("KEY_ALREADY_REVOKED", "That key is already revoked.");
        }
        key.revoke();
        identityKeyRepository.save(key);
        auditService.record(userId, "IDENTITY_KEY_REVOKED", keyId.toString());
        return KeyResponse.of(key);
    }

    /** Public view of any user's keys — what a peer fetches before encrypting. */
    @Transactional(readOnly = true)
    public List<KeyResponse> listForUser(UUID targetUserId) {
        return identityKeyRepository.findByUserIdOrderByKeyVersionDesc(targetUserId).stream()
                .map(KeyResponse::of)
                .toList();
    }

    /**
     * Wire shape. The fingerprint is the SHA-256 of the DER public key,
     * hex-encoded — short enough to read aloud and compare.
     */
    public record KeyResponse(UUID id, UUID userId, String keyType, String publicKey,
                              String fingerprint, int keyVersion,
                              java.time.LocalDateTime createdAt, boolean revoked,
                              java.time.LocalDateTime revokedAt) {
        static KeyResponse of(IdentityKey key) {
            return new KeyResponse(key.getId(), key.getUserId(), key.getKeyType(),
                    key.getPublicKey(), key.getFingerprint(), key.getKeyVersion(),
                    key.getCreatedAt(), key.isRevoked(), key.getRevokedAt());
        }
    }
}
