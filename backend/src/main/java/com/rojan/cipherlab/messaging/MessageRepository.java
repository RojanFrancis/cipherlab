package com.rojan.cipherlab.messaging;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface MessageRepository extends JpaRepository<Message, UUID> {

    List<Message> findByConversationIdOrderByCreatedAtAsc(UUID conversationId);

    boolean existsBySessionIdAndSenderIdAndSequenceNumber(UUID sessionId, UUID senderId, long sequenceNumber);
}
