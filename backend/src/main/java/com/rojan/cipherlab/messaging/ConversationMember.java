package com.rojan.cipherlab.messaging;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * Composite-key join table ({@code conversation_id}, {@code user_id}).
 * Membership is checked on every read and write of the relay: ciphertext
 * from a non-member is rejected before it can reach storage.
 */
@Entity
@Table(name = "conversation_members")
@IdClass(ConversationMember.ConversationMemberId.class)
public class ConversationMember {

    @Id
    @Column(name = "conversation_id")
    private UUID conversationId;

    @Id
    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "joined_at", nullable = false)
    private LocalDateTime joinedAt;

    @PrePersist
    void prePersist() {
        if (joinedAt == null) {
            joinedAt = LocalDateTime.now(java.time.ZoneOffset.UTC);
        }
    }

    public UUID getConversationId() {
        return conversationId;
    }

    public UUID getUserId() {
        return userId;
    }

    public LocalDateTime getJoinedAt() {
        return joinedAt;
    }

    public static ConversationMember of(UUID conversationId, UUID userId) {
        ConversationMember member = new ConversationMember();
        member.conversationId = conversationId;
        member.userId = userId;
        return member;
    }

    /** JPA composite-key value type. */
    public static class ConversationMemberId implements Serializable {
        private UUID conversationId;
        private UUID userId;

        public ConversationMemberId() {
        }

        public ConversationMemberId(UUID conversationId, UUID userId) {
            this.conversationId = conversationId;
            this.userId = userId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof ConversationMemberId other)) {
                return false;
            }
            return Objects.equals(conversationId, other.conversationId)
                    && Objects.equals(userId, other.userId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(conversationId, userId);
        }
    }
}
