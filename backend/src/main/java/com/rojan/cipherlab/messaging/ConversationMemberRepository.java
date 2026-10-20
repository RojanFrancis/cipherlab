package com.rojan.cipherlab.messaging;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ConversationMemberRepository
        extends JpaRepository<ConversationMember, ConversationMember.ConversationMemberId> {

    List<ConversationMember> findByUserId(UUID userId);

    boolean existsByConversationIdAndUserId(UUID conversationId, UUID userId);

    List<ConversationMember> findByConversationId(UUID conversationId);
}
