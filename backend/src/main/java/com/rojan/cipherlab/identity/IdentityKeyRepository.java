package com.rojan.cipherlab.identity;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface IdentityKeyRepository extends JpaRepository<IdentityKey, UUID> {

    List<IdentityKey> findByUserIdOrderByKeyVersionDesc(UUID userId);

    Optional<IdentityKey> findFirstByUserIdOrderByKeyVersionDesc(UUID userId);

    Optional<IdentityKey> findByIdAndUserId(UUID id, UUID userId);

    int countByUserId(UUID userId);
}
