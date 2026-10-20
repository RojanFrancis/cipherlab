package com.rojan.cipherlab.messaging;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CryptoSessionRepository extends JpaRepository<CryptoSession, UUID> {

    List<CryptoSession> findByConversationIdOrderByCreatedAtAsc(UUID conversationId);
}
