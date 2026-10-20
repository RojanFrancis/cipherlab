package com.rojan.cipherlab.messaging;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * Server-side record of an <b>authenticated-handshake</b> encrypted session
 * between two members of a conversation.
 *
 * <p><b>What is deliberately absent:</b> no private keys, no derived
 * secrets, no plaintext. The server stores each side's <em>public</em>
 * ephemeral key and their identity signature over the canonical transcript
 * (see {@link SessionTranscript}) — values that are public by design and
 * that let both the server and the peer <b>verify</b> nobody substituted a
 * key. The shared secret is computed on the clients via ECDH and never
 * leaves browser memory, so a full database compromise still yields only
 * ciphertext, signatures and metadata.
 *
 * <p>Status lifecycle: {@code PENDING} (initiator's signed ephemeral
 * stored) → {@code ACTIVE} (responder's signed ephemeral stored — i.e. the
 * handshake completed and both signatures were verified server-side) →
 * {@code EXPIRED}.
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

    @Column(name = "initiator_ephemeral_public", length = 256)
    private String initiatorEphemeralPublic;

    @Column(name = "initiator_signature", length = 256)
    private String initiatorSignature;

    @Column(name = "initiator_identity_key_id")
    private UUID initiatorIdentityKeyId;

    @Column(name = "responder_ephemeral_public", length = 256)
    private String responderEphemeralPublic;

    @Column(name = "responder_signature", length = 256)
    private String responderSignature;

    @Column(name = "responder_identity_key_id")
    private UUID responderIdentityKeyId;

    @Column(name = "transcript_hash", length = 64)
    private String transcriptHash;

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

    public String getInitiatorEphemeralPublic() {
        return initiatorEphemeralPublic;
    }

    public String getInitiatorSignature() {
        return initiatorSignature;
    }

    public UUID getInitiatorIdentityKeyId() {
        return initiatorIdentityKeyId;
    }

    public String getResponderEphemeralPublic() {
        return responderEphemeralPublic;
    }

    public String getResponderSignature() {
        return responderSignature;
    }

    public UUID getResponderIdentityKeyId() {
        return responderIdentityKeyId;
    }

    public String getTranscriptHash() {
        return transcriptHash;
    }

    public boolean isParticipant(UUID userId) {
        return initiatorId.equals(userId) || responderId.equals(userId);
    }

    public void activate(LocalDateTime expiry) {
        this.status = STATUS_ACTIVE;
        this.expiresAt = expiry;
    }

    /** Stores the responder's verified handshake material and the agreed transcript hash. */
    public void completeHandshake(String responderEphemeralPublic, String responderSignature,
                                  UUID responderIdentityKeyId, String transcriptHash) {
        this.responderEphemeralPublic = responderEphemeralPublic;
        this.responderSignature = responderSignature;
        this.responderIdentityKeyId = responderIdentityKeyId;
        this.transcriptHash = transcriptHash;
    }

    public boolean isExpiredAt(LocalDateTime now) {
        return expiresAt != null && now.isAfter(expiresAt);
    }

    public static CryptoSession create(UUID id, UUID conversationId, UUID initiatorId,
                                       UUID responderId, String suite,
                                       String initiatorEphemeralPublic, String initiatorSignature,
                                       UUID initiatorIdentityKeyId) {
        CryptoSession session = new CryptoSession();
        session.id = id;
        session.conversationId = conversationId;
        session.initiatorId = initiatorId;
        session.responderId = responderId;
        session.suite = suite;
        session.status = STATUS_PENDING;
        session.initiatorEphemeralPublic = initiatorEphemeralPublic;
        session.initiatorSignature = initiatorSignature;
        session.initiatorIdentityKeyId = initiatorIdentityKeyId;
        return session;
    }
}
