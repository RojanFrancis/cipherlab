package com.rojan.cipherlab.messaging;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * Server-side record of an end-to-end encrypted session between two members
 * of a conversation.
 *
 * <p><b>What is deliberately absent:</b> no keys, no derived secrets, no
 * plaintext. The server tracks lifecycle only — who, which suite, status,
 * expiry. The actual key agreement happens on the clients (using the same
 * primitives the lab teaches), so a full database compromise still yields
 * only ciphertext and metadata.
 *
 * <p>Status lifecycle: {@code PENDING} (initiator created) → {@code ACTIVE}
 * (responder confirmed their ephemeral public key) → {@code EXPIRED}.
 */
@Entity
@Table(name = "crypto_sessions")
public class CryptoSession {

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "conversation_id", nullable = false)
    private UUID conversationId;

    @Column(name = "initiator_id", nullable = false)
    private UUID initiatorId;

    @Column(name = "responder_id", nullable = false)
    private UUID responderId;

    @Column(name = "suite", nullable = false, length = 64)
    private String suite;

    @Column(name = "status", nullable = false, length = 32)
    private String status;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_EXPIRED = "EXPIRED";

    @PrePersist
    void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now(java.time.ZoneOffset.UTC);
        }
        if (status == null) {
            status = STATUS_PENDING;
        }
    }

    public UUID getId() {
        return id;
    }

    public UUID getConversationId() {
        return conversationId;
    }

    public UUID getInitiatorId() {
        return initiatorId;
    }

    public UUID getResponderId() {
        return responderId;
    }

    public String getSuite() {
        return suite;
    }

    public String getStatus() {
        return status;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public boolean isParticipant(UUID userId) {
        return initiatorId.equals(userId) || responderId.equals(userId);
    }

    public void activate(LocalDateTime expiry) {
        this.status = STATUS_ACTIVE;
        this.expiresAt = expiry;
    }

    public boolean isExpiredAt(LocalDateTime now) {
        return expiresAt != null && now.isAfter(expiresAt);
    }

    public static CryptoSession create(UUID conversationId, UUID initiatorId,
                                       UUID responderId, String suite) {
        CryptoSession session = new CryptoSession();
        session.id = UUID.randomUUID();
        session.conversationId = conversationId;
        session.initiatorId = initiatorId;
        session.responderId = responderId;
        session.suite = suite;
        session.status = STATUS_PENDING;
        return session;
    }
}
