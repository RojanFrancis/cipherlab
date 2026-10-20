package com.rojan.cipherlab.common;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * Security-relevant event trail (spec §8). One row per notable action —
 * logins, key publication, session lifecycle, replay rejections. Contains
 * <b>metadata only</b>: no tokens, no keys, no ciphertext, no plaintext.
 */
@Entity
@Table(name = "audit_events")
public class AuditEvent {

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "actor_id")
    private UUID actorId;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    @Column(name = "resource_id")
    private String resourceId;

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

    public UUID getActorId() {
        return actorId;
    }

    public String getEventType() {
        return eventType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public static AuditEvent of(UUID actorId, String eventType, String resourceId) {
        AuditEvent event = new AuditEvent();
        event.id = UUID.randomUUID();
        event.actorId = actorId;
        event.eventType = eventType;
        event.resourceId = resourceId;
        return event;
    }
}
