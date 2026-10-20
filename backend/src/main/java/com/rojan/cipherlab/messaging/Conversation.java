package com.rojan.cipherlab.messaging;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * A conversation is the membership boundary for message relay. It holds no
 * cryptographic material at all — the server manages <b>who may talk to
 * whom</b>, the clients manage <b>how</b> the traffic is protected.
 */
@Entity
@Table(name = "conversations")
public class Conversation {

    @Id
    @Column(name = "id")
    private UUID id;

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

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public static Conversation create() {
        Conversation conversation = new Conversation();
        conversation.id = UUID.randomUUID();
        return conversation;
    }
}
