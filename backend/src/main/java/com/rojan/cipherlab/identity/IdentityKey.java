package com.rojan.cipherlab.identity;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * A published <b>public</b> identity key. The private half never touches the
 * server: the client generates the keypair locally and uploads only the
 * public key, which is why this row can be stored in the clear.
 *
 * <p>{@code key_version} supports rotation without history loss — the unique
 * {@code (user_id, key_version)} index means old versions remain resolvable
 * (for verifying old signatures) while {@code revoked_at} marks the cut-off.
 */
@Entity
@Table(name = "identity_keys")
public class IdentityKey {

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "key_type", nullable = false, length = 32)
    private String keyType;

    @Column(name = "public_key", nullable = false, length = 512)
    private String publicKey;

    @Column(name = "fingerprint", nullable = false, length = 128)
    private String fingerprint;

    @Column(name = "key_version", nullable = false)
    private int keyVersion;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    @PrePersist
    void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now(java.time.ZoneOffset.UTC);
        }
    }

    public UUID getId() {
        return id;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getKeyType() {
        return keyType;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public int getKeyVersion() {
        return keyVersion;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getRevokedAt() {
        return revokedAt;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public void revoke() {
        this.revokedAt = LocalDateTime.now(java.time.ZoneOffset.UTC);
    }

    public static IdentityKey create(UUID userId, String keyType, String publicKey,
                                     String fingerprint, int keyVersion) {
        IdentityKey key = new IdentityKey();
        key.id = UUID.randomUUID();
        key.userId = userId;
        key.keyType = keyType;
        key.publicKey = publicKey;
        key.fingerprint = fingerprint;
        key.keyVersion = keyVersion;
        return key;
    }
}
