package com.rojan.cipherlab.auth;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * Application user. The only secret this table holds is a <b>BCrypt</b>
 * password hash — a slow, salted, adaptive KDF, deliberately different from
 * the fast hashes taught in the lab (SHA-256 is for integrity, not for
 * storing passwords).
 *
 * <p>UUIDs are assigned by the application (never accepted from a client),
 * per the schema rules in {@code V1__initial_schema.sql}.
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "username", nullable = false, length = 64, unique = true)
    private String username;

    @Column(name = "email", nullable = false, length = 255, unique = true)
    private String email;

    /** BCrypt hash — never serialized, never returned by any API. */
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

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

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public static User create(String username, String email, String passwordHash) {
        User user = new User();
        user.username = username;
        user.email = email;
        user.passwordHash = passwordHash;
        return user;
    }
}
