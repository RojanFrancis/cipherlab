package com.rojan.cipherlab.messaging;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * A relayed message. The server stores exactly three things about the
 * payload: a sequence number, a nonce, and the <b>ciphertext</b> — it can
 * route and deduplicate but never read.
 *
 * <p>The unique index {@code (session_id, sender_id, sequence_number)} is
 * the server-side replay defense: a sender that re-submits a (session,
 * sequence) pair violates the constraint, and the relay rejects it with
 * {@code REPLAYED_MESSAGE} — <em>without</em> needing to decrypt anything.
 */
@Entity
@Table(name = "messages")
public class Message {

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "conversation_id", nullable = false)
    private UUID conversationId;

    @Column(name = "session_id", nullable = false)
    private UUID sessionId;

    @Column(name = "sender_id", nullable = false)
    private UUID senderId;

    @Column(name = "sequence_number", nullable = false)
    private long sequenceNumber;

    @Column(name = "nonce", nullable = false, length = 64)
    private String nonce;

    @Column(name = "ciphertext", nullable = false)
    private String ciphertext;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

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

    public UUID getConversationId() {
        return conversationId;
    }

    public UUID getSessionId() {
        return sessionId;
    }

    public UUID getSenderId() {
        return senderId;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public String getNonce() {
        return nonce;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public static Message relayed(UUID conversationId, UUID sessionId, UUID senderId,
                                  long sequenceNumber, String nonce, String ciphertext) {
        Message message = new Message();
        message.id = UUID.randomUUID();
        message.conversationId = conversationId;
        message.sessionId = sessionId;
        message.senderId = senderId;
        message.sequenceNumber = sequenceNumber;
        message.nonce = nonce;
        message.ciphertext = ciphertext;
        return message;
    }
}
