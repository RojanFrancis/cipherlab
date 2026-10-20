package com.rojan.cipherlab.security;

import java.util.UUID;

/**
 * The authenticated principal stored in the security context after a JWT
 * passes verification. Deliberately tiny: identity only, no authorities
 * beyond the implicit ROLE_USER (v1 has a single role).
 */
public record AuthenticatedUser(UUID userId, String username) {
}
