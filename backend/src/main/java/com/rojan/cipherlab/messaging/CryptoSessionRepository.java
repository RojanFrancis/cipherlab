package com.rojan.cipherlab.messaging;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CryptoSessionRepository extends JpaRepository<CryptoSession, UUID> {

    boolean existsByIdAndInitiatorId(UUID id, UUID initiatorId);

    boolean existsByIdAndResponderId(UUID id, UUID responderId);
}
